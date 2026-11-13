//! The component tree a window's view returns: Egrio's own components, their
//! properties and the messages their events produce. The set is closed and
//! serves Egrio's pages only; a page that needs a new element adds a
//! component here and every backend implements it once.
//!
//! A handler never takes part in comparison: two handlers are always equal,
//! so a new closure causes no patch, and an event runs the handler of the
//! newest tree.

use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;
use std::sync::Arc;

use crate::msg::Msg;

/// Turns an event's value into a message.
pub struct Handler<T>(Rc<dyn Fn(T) -> Msg>);

impl<T> Handler<T> {
    pub fn new(map: impl Fn(T) -> Msg + 'static) -> Self {
        Self(Rc::new(map))
    }

    pub fn call(&self, value: T) -> Msg {
        (self.0)(value)
    }
}

impl Handler<()> {
    /// A handler that always sends `msg`.
    pub fn send(msg: Msg) -> Self {
        Self::new(move |()| msg.clone())
    }
}

impl<T> Clone for Handler<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> PartialEq for Handler<T> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<T> fmt::Debug for Handler<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Handler")
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    /// Identity among siblings: keyed children keep their native control when
    /// they move; unkeyed children match by position.
    pub key: Option<String>,
    pub attrs: Attrs,
    pub kind: Kind,
    pub children: Vec<Node>,
}

/// Layout and help that any component takes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Attrs {
    /// Takes the space left along the parent stack's axis.
    pub grow: bool,
    pub width: Option<f64>,
    pub height: Option<f64>,
    pub tooltip: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    /// Children in a line.
    Stack(Stack),
    /// A content surface; its children stack vertically inside.
    Card(Card),
    /// Two panes side by side: the first child leads, the second takes the rest.
    Split(Split),
    /// Flexible empty space in a stack.
    Spacer,
    /// A thin line across a vertical stack, between two of its parts.
    Separator,
    Text(Text),
    Badge(Badge),
    /// A symbol in a tone.
    Symbol(Symbol),
    Button(Button),
    Segmented(Segmented),
    /// A line of label and value pairs summing up the content around it.
    Facts(Facts),
    /// Labelled values in a grid, the label above its value.
    Fields(Fields),
    Table(Table),
    /// Tiles of one size in rows across the width.
    Tiles(Tiles),
    Chart(Chart),
    Spinner,
    /// What an empty or unavailable view shows instead of its content.
    Placeholder(Placeholder),
    /// A vertical scroll area around its one child, which keeps its natural
    /// height and scrolls once it is taller than the area.
    Scroll,
    /// An on/off switch.
    Switch(Switch),
    /// One choice from a short list, shown as the chosen option.
    Select(Select),
    /// One of a set, chosen or not; pressing an unchosen one asks to choose it.
    Radio(Radio),
    /// Text the user can edit in place: a click starts editing, Return or
    /// leaving it commits, Esc goes back to the text.
    EditableText(EditableText),
    /// A text field: it reports every edit; its value is written back only
    /// when the interface's value differs from the last one it reported, so
    /// an input method's composition is never interrupted.
    TextField(TextField),
    /// A text field in the platform's search look, with a button that
    /// clears it; it reports and is written back like a text field.
    SearchField(TextField),
    /// Plain text over many lines in a monospaced font, a document the user
    /// writes; it reports and is written back like a text field.
    TextEditor(TextEditor),
    /// A button that opens a panel beside it, its one child the panel's
    /// content; the panel closes when the user clicks elsewhere or presses
    /// Esc. Whether it is open is the platform's to keep.
    Popover(Popover),
    /// A titled group of setting rows on one surface; its children are rows.
    Group(Group),
    /// A setting: its name and explanation, its children (the controls) at
    /// the end.
    SettingRow(SettingRow),
}

impl Kind {
    pub(crate) fn same_component(&self, other: &Self) -> bool {
        match (self, other) {
            // A stack's line and where its children sit come from its axis
            // and alignment, so changing either makes another stack.
            (Kind::Stack(old), Kind::Stack(new)) => old.axis == new.axis && old.align == new.align,
            _ => std::mem::discriminant(self) == std::mem::discriminant(other),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    Vertical,
    Horizontal,
}

/// Where children sit across the stack's axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossAlign {
    Start,
    Center,
    End,
    /// Children take the stack's whole width (vertical) or height (horizontal).
    Fill,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Stack {
    pub axis: Axis,
    pub spacing: f64,
    pub align: CrossAlign,
    /// Space between the stack's edges and its children.
    pub padding: Padding,
}

/// Space inside a component's edges: at its sides and at its top and bottom.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Padding {
    pub horizontal: f64,
    pub vertical: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Card {
    /// Padding inside the surface; zero for a list that runs to its edges.
    pub padding: f64,
    pub spacing: f64,
    /// The one of a set that is in use, shown with the accent edge.
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Split {
    /// The leading pane's width.
    pub leading: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextStyle {
    /// A page or card heading.
    Heading,
    Body,
    /// Small explanatory or secondary text.
    Caption,
    /// A large figure, such as a rate.
    Figure,
    Mono,
}

/// The meaning a color carries; each backend maps it to its platform's colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tone {
    Default,
    Muted,
    Faint,
    Accent,
    Success,
    Warning,
    Danger,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Text {
    pub text: String,
    pub style: TextStyle,
    pub tone: Tone,
    /// One line, cut with an ellipsis when it does not fit.
    pub single_line: bool,
    pub selectable: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Badge {
    pub text: String,
    pub tone: Tone,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Symbol {
    pub icon: Icon,
    pub tone: Tone,
}

/// Symbols a component may show; each backend maps them to its platform's
/// symbol set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Icon {
    Activity,
    Nodes,
    Profiles,
    Rules,
    Connections,
    Logs,
    Settings,
    Download,
    Upload,
    Clear,
    Close,
    Warning,
    Messages,
    App,
    Globe,
    /// TUN mode's one-time environment.
    Wrench,
    Add,
    Edit,
    Reapply,
    Delete,
    /// A latency test.
    Zap,
    /// A link, such as a node's own test URL.
    Link,
    /// Where traffic would go.
    Route,
    /// Fetching something again.
    Refresh,
    /// Counts starting from zero again.
    ResetCount,
    /// The one of a set in use.
    Check,
}

/// A dialog's keys: Return presses its default button, Esc its cancel button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonKey {
    Return,
    Escape,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ButtonStyle {
    Primary,
    Secondary,
    /// No bezel until hovered, for toolbars and card corners.
    Plain,
    Destructive,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Button {
    pub label: Option<String>,
    pub icon: Option<Icon>,
    /// The color of its symbol.
    pub tone: Tone,
    pub style: ButtonStyle,
    /// The key that presses it in a dialog.
    pub key: Option<ButtonKey>,
    pub enabled: bool,
    /// Work it started is running: it shows progress and takes no presses.
    pub busy: bool,
    pub on_press: Option<Handler<()>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Segmented {
    pub options: Vec<String>,
    pub selected: Option<usize>,
    pub enabled: bool,
    pub on_select: Option<Handler<usize>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub label: String,
    pub value: String,
    pub mono: bool,
    /// Something about the value needs attention: a warning mark beside it,
    /// with this explanation as its tooltip.
    pub warning: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Facts {
    pub items: Vec<Fact>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub label: String,
    /// One line each; several for a field with more than one value.
    pub values: Vec<String>,
    pub mono: bool,
    /// Spans the whole row and wraps, for long text.
    pub wide: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fields {
    pub columns: usize,
    pub items: Vec<Field>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ColumnWidth {
    Fixed(f64),
    /// Takes the width the fixed columns leave, never less than `min`.
    Flexible {
        min: f64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnAlign {
    Leading,
    Trailing,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Column {
    pub title: String,
    pub width: ColumnWidth,
    pub align: ColumnAlign,
    pub sortable: bool,
}

/// A table cell's content; a backend draws each kind the same way in every
/// row, so rows of a few thousand stay cheap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cell {
    Text {
        text: String,
        tone: Tone,
        mono: bool,
    },
    Badge {
        text: String,
        tone: Tone,
    },
    /// A colored dot before the text.
    Status {
        text: String,
        tone: Tone,
    },
    /// An app icon (or a neutral glyph without one) before the name.
    Process {
        name: String,
        icon: Option<Image>,
    },
    /// Right-aligned, with figures of equal width.
    Number(String),
    /// A title over a secondary line, with an optional figure at the end.
    TwoLine {
        title: String,
        detail: String,
        icon: Option<Image>,
        fallback: Icon,
        trailing: String,
        /// The figure's color.
        trailing_tone: Tone,
    },
    /// Cells in one column: the first at its start, cut where it meets the
    /// rest, the others, its tags, side by side at its end.
    Inline(Vec<Cell>),
}

/// A PNG image, compared by identity: the same `Arc` is the same image.
#[derive(Debug, Clone)]
pub struct Image(pub Arc<[u8]>);

impl PartialEq for Image {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for Image {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Unique among the table's rows.
    pub key: String,
    pub cells: Vec<Cell>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection {
    None,
    Single,
    Multiple,
}

#[derive(Debug, Clone)]
pub struct Table {
    pub columns: Vec<Column>,
    /// The set and each row are shared: unchanged sets cost one pointer
    /// comparison, and reordered rows keep their rendered cells.
    pub rows: Rc<Vec<Rc<Row>>>,
    pub header: bool,
    pub row_height: f64,
    pub selection: Selection,
    /// Keys of the selected rows.
    pub selected: Vec<String>,
    pub sort: Option<(usize, SortDirection)>,
    /// What the table shows while it has no rows.
    pub empty: Option<String>,
    /// Keeps the last row in view as rows arrive, while the table is
    /// scrolled to its end.
    pub follow_end: bool,
    /// Text cells wrap and each row grows to show all of its text;
    /// `row_height` is then the least a row takes.
    pub wrap: bool,
    pub on_select: Option<Handler<Vec<String>>>,
    pub on_activate: Option<Handler<String>>,
    pub on_sort: Option<Handler<Option<(usize, SortDirection)>>>,
    /// Rows can be dragged to another place: the keys of the rows dragged,
    /// and the row of the order shown they were dropped before (the row
    /// count for the end).
    pub on_move: Option<Handler<(Vec<String>, usize)>>,
}

impl PartialEq for Table {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.rows, &other.rows)
            && self.columns == other.columns
            && self.header == other.header
            && self.row_height == other.row_height
            && self.selection == other.selection
            && self.selected == other.selected
            && self.sort == other.sort
            && self.empty == other.empty
            && self.follow_end == other.follow_end
            && self.wrap == other.wrap
            // Whether rows can be dragged is the backend's to know.
            && self.on_move.is_some() == other.on_move.is_some()
    }
}

/// `order` after the rows with the keys `moved` are taken out and put, in
/// the order they had, before the row that was at `to` (the end when `to`
/// is past the last row or names a row that moved).
pub fn moved_order(order: &[String], moved: &[String], to: usize) -> Vec<String> {
    let moving: std::collections::HashSet<&str> = moved.iter().map(String::as_str).collect();
    let before = order.get(to).filter(|key| !moving.contains(key.as_str()));
    let mut kept: Vec<String> = order
        .iter()
        .filter(|key| !moving.contains(key.as_str()))
        .cloned()
        .collect();
    let at = before
        .and_then(|before| kept.iter().position(|key| key == before))
        .unwrap_or_else(|| {
            // Dropped on a moving row or past the end: after the rows
            // before it that stay.
            order[..to.min(order.len())]
                .iter()
                .filter(|key| !moving.contains(key.as_str()))
                .count()
        });
    let taken: Vec<String> = order
        .iter()
        .filter(|key| moving.contains(key.as_str()))
        .cloned()
        .collect();
    kept.splice(at..at, taken);
    kept
}

/// How the items of a keyed list (a table's rows, a grid's tiles) changed
/// between two renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyedChanges {
    None,
    /// Items came and went while the items kept stayed in order: remove
    /// `removed` (indexes into the old items), then insert `inserted` and
    /// redraw `changed` (indexes into the new items), each ascending.
    Edit {
        removed: Vec<usize>,
        inserted: Vec<usize>,
        changed: Vec<usize>,
    },
    /// The items kept changed order: reload them all, keeping the selection by key.
    Reload,
}

/// How `new` differs from `old`, items matched by `key`.
pub fn keyed_changes<T: PartialEq>(new: &[T], old: &[T], key: impl Fn(&T) -> &str) -> KeyedChanges {
    let positions: HashMap<&str, usize> = new
        .iter()
        .enumerate()
        .map(|(index, item)| (key(item), index))
        .collect();
    let mut kept = vec![false; new.len()];
    let (mut removed, mut changed) = (Vec::new(), Vec::new());
    let mut last = None;
    for (index, item) in old.iter().enumerate() {
        let Some(&position) = positions.get(key(item)) else {
            removed.push(index);
            continue;
        };
        if last.is_some_and(|last| position <= last) {
            return KeyedChanges::Reload;
        }
        last = Some(position);
        kept[position] = true;
        if new[position] != *item {
            changed.push(position);
        }
    }
    let inserted: Vec<usize> = (0..new.len()).filter(|index| !kept[*index]).collect();
    if removed.is_empty() && inserted.is_empty() && changed.is_empty() {
        KeyedChanges::None
    } else {
        KeyedChanges::Edit {
            removed,
            inserted,
            changed,
        }
    }
}

impl Table {
    pub fn row_changes(&self, old: &Table) -> KeyedChanges {
        if Rc::ptr_eq(&self.rows, &old.rows) {
            return KeyedChanges::None;
        }
        keyed_changes(&self.rows, &old.rows, |row| row.key.as_str())
    }
}

/// Tiles of one size in rows that fill the width: as many to a row as fit at
/// `min_width`, sharing the row's width. The backend builds views only for
/// the tiles it shows, as a table does for its rows.
#[derive(Debug, Clone)]
pub struct Tiles {
    pub tiles: Rc<Vec<Tile>>,
    /// The narrowest a tile gets.
    pub min_width: f64,
    pub height: f64,
    /// What shows while there are no tiles.
    pub empty: Option<String>,
    /// The name and help of a tile's test button.
    pub test_label: String,
    /// The selected tile carries a check mark after its title, for a choice
    /// in use; without it the accent edge alone marks the one shown.
    pub check: bool,
    /// A pressed tile's key.
    pub on_press: Option<Handler<String>>,
    /// The key of a tile whose test button was pressed.
    pub on_test: Option<Handler<String>>,
}

/// Tiles compare by identity first, so a page that reuses them costs a
/// pointer comparison, then by content.
impl PartialEq for Tiles {
    fn eq(&self, other: &Self) -> bool {
        (Rc::ptr_eq(&self.tiles, &other.tiles) || self.tiles == other.tiles)
            && self.min_width == other.min_width
            && self.height == other.height
            && self.empty == other.empty
            && self.test_label == other.test_label
            && self.check == other.check
    }
}

impl Tiles {
    pub fn tile_changes(&self, old: &Tiles) -> KeyedChanges {
        keyed_changes(&self.tiles, &old.tiles, |tile| tile.key.as_str())
    }
}

/// One tile: its title over a line of what it is, a detail and a value at
/// the end.
#[derive(Debug, Clone, PartialEq)]
pub struct Tile {
    /// Unique among the tiles.
    pub key: String,
    pub title: String,
    /// What the tile stands for, at the start of its second line.
    pub kind: String,
    /// After the kind, fainter, cut when it does not fit.
    pub detail: Option<String>,
    /// A symbol after the detail.
    pub mark: Option<Icon>,
    pub value: TileValue,
    /// The one of the set in use or shown: drawn with the accent edge, and
    /// a check mark after the title where the grid checks its selection.
    pub selected: bool,
    /// Pressing it reports its key.
    pub pressable: bool,
    /// Its value is a button of its own that reports a test of it; without
    /// a value the button shows the test symbol.
    pub testable: bool,
    /// Drawn faded: what it stands for cannot be used.
    pub dimmed: bool,
    pub tooltip: Option<String>,
}

/// The end of a tile's second line.
#[derive(Debug, Clone, PartialEq)]
pub enum TileValue {
    None,
    Text {
        text: String,
        tone: Tone,
    },
    /// Work for the tile is running.
    Progress,
}

/// A path in a 100 × 100 box, y growing downwards; the backend stretches the
/// box to the view's bounds and keeps the stroke width.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Path(pub Vec<PathCommand>);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PathCommand {
    Move(f64, f64),
    Line(f64, f64),
    Curve {
        control1: (f64, f64),
        control2: (f64, f64),
        to: (f64, f64),
    },
    Close,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Chart {
    pub download_area: Path,
    pub download_line: Path,
    pub upload_area: Path,
    pub upload_line: Path,
    /// What the chart shows, for assistive technologies.
    pub description: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Placeholder {
    pub title: String,
    pub detail: Option<String>,
    /// What the user can do about it: a primary button under the text.
    pub action: Option<PlaceholderAction>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PlaceholderAction {
    pub label: String,
    pub icon: Option<Icon>,
    pub on_press: Handler<()>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Switch {
    pub on: bool,
    pub enabled: bool,
    pub on_toggle: Option<Handler<bool>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Select {
    pub options: Vec<String>,
    pub selected: Option<usize>,
    pub enabled: bool,
    pub on_select: Option<Handler<usize>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Radio {
    pub selected: bool,
    pub enabled: bool,
    pub on_select: Option<Handler<()>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EditableText {
    pub text: String,
    pub style: TextStyle,
    pub enabled: bool,
    /// The edited text, when the user committed a change.
    pub on_commit: Option<Handler<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TextField {
    pub value: String,
    pub placeholder: String,
    pub enabled: bool,
    pub on_change: Option<Handler<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TextEditor {
    /// Shared with the interface state, so an unchanged document costs a
    /// pointer comparison.
    pub text: Arc<str>,
    pub enabled: bool,
    pub on_change: Option<Handler<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Popover {
    pub label: String,
    pub icon: Option<Icon>,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Group {
    pub title: String,
    /// Why the whole group is unavailable, beside its title.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SettingRow {
    pub label: String,
    pub description: Option<String>,
}

impl Node {
    fn leaf(kind: Kind) -> Self {
        Self {
            key: None,
            attrs: Attrs::default(),
            kind,
            children: Vec::new(),
        }
    }

    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    pub fn grow(mut self) -> Self {
        self.attrs.grow = true;
        self
    }

    pub fn width(mut self, width: f64) -> Self {
        self.attrs.width = Some(width);
        self
    }

    pub fn height(mut self, height: f64) -> Self {
        self.attrs.height = Some(height);
        self
    }

    pub fn tooltip(mut self, tooltip: Option<String>) -> Self {
        self.attrs.tooltip = tooltip;
        self
    }

    /// Space inside a stack's edges; only stacks take it.
    pub fn padding(mut self, horizontal: f64, vertical: f64) -> Self {
        match &mut self.kind {
            Kind::Stack(stack) => {
                stack.padding = Padding {
                    horizontal,
                    vertical,
                }
            }
            _ => debug_assert!(false, "padding on a {:?}", self.kind),
        }
        self
    }
}

pub fn column(spacing: f64, children: Vec<Node>) -> Node {
    stack(Axis::Vertical, spacing, CrossAlign::Fill, children)
}

pub fn row(spacing: f64, children: Vec<Node>) -> Node {
    stack(Axis::Horizontal, spacing, CrossAlign::Center, children)
}

pub fn stack(axis: Axis, spacing: f64, align: CrossAlign, children: Vec<Node>) -> Node {
    Node {
        children,
        ..Node::leaf(Kind::Stack(Stack {
            axis,
            spacing,
            align,
            padding: Padding::default(),
        }))
    }
}

pub fn card(children: Vec<Node>) -> Node {
    Node {
        children,
        ..Node::leaf(Kind::Card(Card {
            padding: 16.0,
            spacing: 12.0,
            selected: false,
        }))
    }
}

/// A compact card for one of a list, `selected` when it is the one in use.
pub fn list_card(selected: bool, children: Vec<Node>) -> Node {
    Node {
        children,
        ..Node::leaf(Kind::Card(Card {
            padding: 12.0,
            spacing: 6.0,
            selected,
        }))
    }
}

pub fn flush_card(children: Vec<Node>) -> Node {
    Node {
        children,
        ..Node::leaf(Kind::Card(Card {
            padding: 0.0,
            spacing: 0.0,
            selected: false,
        }))
    }
}

pub fn split(leading: f64, first: Node, second: Node) -> Node {
    Node {
        children: vec![first, second],
        ..Node::leaf(Kind::Split(Split { leading }))
    }
}

pub fn spacer() -> Node {
    Node::leaf(Kind::Spacer).grow()
}

pub fn separator() -> Node {
    Node::leaf(Kind::Separator)
}

pub fn text(text: impl Into<String>, style: TextStyle, tone: Tone) -> Node {
    Node::leaf(Kind::Text(Text {
        text: text.into(),
        style,
        tone,
        single_line: true,
        selectable: false,
    }))
}

pub fn heading(value: impl Into<String>) -> Node {
    text(value, TextStyle::Heading, Tone::Default)
}

pub fn caption(value: impl Into<String>) -> Node {
    text(value, TextStyle::Caption, Tone::Muted)
}

/// Wrapping, selectable text.
pub fn paragraph(value: impl Into<String>, tone: Tone) -> Node {
    Node::leaf(Kind::Text(Text {
        text: value.into(),
        style: TextStyle::Body,
        tone,
        single_line: false,
        selectable: true,
    }))
}

pub fn badge(value: impl Into<String>, tone: Tone) -> Node {
    Node::leaf(Kind::Badge(Badge {
        text: value.into(),
        tone,
    }))
}

pub fn symbol(icon: Icon, tone: Tone) -> Node {
    Node::leaf(Kind::Symbol(Symbol { icon, tone }))
}

pub fn button(label: impl Into<String>, style: ButtonStyle) -> ButtonBuilder {
    ButtonBuilder(Button {
        label: Some(label.into()),
        icon: None,
        tone: Tone::Default,
        style,
        key: None,
        enabled: true,
        busy: false,
        on_press: None,
    })
}

pub fn icon_button(icon: Icon) -> ButtonBuilder {
    ButtonBuilder(Button {
        label: None,
        icon: Some(icon),
        tone: Tone::Default,
        style: ButtonStyle::Plain,
        key: None,
        enabled: true,
        busy: false,
        on_press: None,
    })
}

pub struct ButtonBuilder(Button);

impl ButtonBuilder {
    pub fn icon(mut self, icon: Icon) -> Self {
        self.0.icon = Some(icon);
        self
    }

    pub fn enabled(mut self, enabled: bool) -> Self {
        self.0.enabled = enabled;
        self
    }

    pub fn tone(mut self, tone: Tone) -> Self {
        self.0.tone = tone;
        self
    }

    pub fn key(mut self, key: ButtonKey) -> Self {
        self.0.key = Some(key);
        self
    }

    pub fn busy(mut self, busy: bool) -> Self {
        self.0.busy = busy;
        self
    }

    pub fn on_press(mut self, msg: Msg) -> Node {
        self.0.on_press = Some(Handler::send(msg));
        Node::leaf(Kind::Button(self.0))
    }
}

pub fn segmented(
    options: Vec<String>,
    selected: Option<usize>,
    enabled: bool,
    on_select: impl Fn(usize) -> Msg + 'static,
) -> Node {
    Node::leaf(Kind::Segmented(Segmented {
        options,
        selected,
        enabled,
        on_select: Some(Handler::new(on_select)),
    }))
}

pub fn facts(items: Vec<Fact>) -> Node {
    Node::leaf(Kind::Facts(Facts { items }))
}

pub fn fact(label: impl Into<String>, value: impl Into<String>) -> Fact {
    Fact {
        label: label.into(),
        value: value.into(),
        mono: false,
        warning: None,
    }
}

pub fn fields(columns: usize, items: Vec<Field>) -> Node {
    Node::leaf(Kind::Fields(Fields { columns, items }))
}

pub fn field(label: impl Into<String>, value: impl Into<String>) -> Field {
    Field {
        label: label.into(),
        values: vec![value.into()],
        mono: false,
        wide: false,
    }
}

pub fn table(table: Table) -> Node {
    Node::leaf(Kind::Table(table))
}

pub fn tiles(tiles: Tiles) -> Node {
    Node::leaf(Kind::Tiles(tiles))
}

pub fn chart(chart: Chart) -> Node {
    Node::leaf(Kind::Chart(chart))
}

pub fn spinner() -> Node {
    Node::leaf(Kind::Spinner)
}

pub fn placeholder(title: impl Into<String>, detail: Option<String>) -> Node {
    Node::leaf(Kind::Placeholder(Placeholder {
        title: title.into(),
        detail,
        action: None,
    }))
}

/// A placeholder with a button that does something about it.
pub fn placeholder_with_action(
    title: impl Into<String>,
    label: impl Into<String>,
    icon: Option<Icon>,
    on_press: Msg,
) -> Node {
    Node::leaf(Kind::Placeholder(Placeholder {
        title: title.into(),
        detail: None,
        action: Some(PlaceholderAction {
            label: label.into(),
            icon,
            on_press: Handler::send(on_press),
        }),
    }))
}

pub fn switch(on: bool, enabled: bool, on_toggle: impl Fn(bool) -> Msg + 'static) -> Node {
    Node::leaf(Kind::Switch(Switch {
        on,
        enabled,
        on_toggle: Some(Handler::new(on_toggle)),
    }))
}

pub fn select(
    options: Vec<String>,
    selected: Option<usize>,
    enabled: bool,
    on_select: impl Fn(usize) -> Msg + 'static,
) -> Node {
    Node::leaf(Kind::Select(Select {
        options,
        selected,
        enabled,
        on_select: Some(Handler::new(on_select)),
    }))
}

pub fn text_field(
    value: impl Into<String>,
    placeholder: impl Into<String>,
    enabled: bool,
    on_change: impl Fn(String) -> Msg + 'static,
) -> Node {
    Node::leaf(Kind::TextField(TextField {
        value: value.into(),
        placeholder: placeholder.into(),
        enabled,
        on_change: Some(Handler::new(on_change)),
    }))
}

pub fn search_field(
    value: impl Into<String>,
    placeholder: impl Into<String>,
    on_change: impl Fn(String) -> Msg + 'static,
) -> Node {
    Node::leaf(Kind::SearchField(TextField {
        value: value.into(),
        placeholder: placeholder.into(),
        enabled: true,
        on_change: Some(Handler::new(on_change)),
    }))
}

pub fn text_editor(
    text: Arc<str>,
    enabled: bool,
    on_change: impl Fn(String) -> Msg + 'static,
) -> Node {
    Node::leaf(Kind::TextEditor(TextEditor {
        text,
        enabled,
        on_change: Some(Handler::new(on_change)),
    }))
}

pub fn radio(selected: bool, enabled: bool, on_select: Msg) -> Node {
    Node::leaf(Kind::Radio(Radio {
        selected,
        enabled,
        on_select: Some(Handler::send(on_select)),
    }))
}

pub fn editable_text(
    text: impl Into<String>,
    style: TextStyle,
    enabled: bool,
    on_commit: impl Fn(String) -> Msg + 'static,
) -> Node {
    Node::leaf(Kind::EditableText(EditableText {
        text: text.into(),
        style,
        enabled,
        on_commit: Some(Handler::new(on_commit)),
    }))
}

pub fn popover(label: impl Into<String>, icon: Option<Icon>, enabled: bool, content: Node) -> Node {
    Node {
        children: vec![content],
        ..Node::leaf(Kind::Popover(Popover {
            label: label.into(),
            icon,
            enabled,
        }))
    }
}

pub fn group(title: impl Into<String>, note: Option<String>, rows: Vec<Node>) -> Node {
    Node {
        children: rows,
        ..Node::leaf(Kind::Group(Group {
            title: title.into(),
            note,
        }))
    }
}

pub fn setting_row(
    label: impl Into<String>,
    description: Option<String>,
    controls: Vec<Node>,
) -> Node {
    Node {
        children: controls,
        ..Node::leaf(Kind::SettingRow(SettingRow {
            label: label.into(),
            description,
        }))
    }
}

pub fn scroll(child: Node) -> Node {
    Node {
        children: vec![child],
        ..Node::leaf(Kind::Scroll)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(keys: &[(&str, &str)]) -> Rc<Vec<Rc<Row>>> {
        Rc::new(
            keys.iter()
                .map(|(key, value)| {
                    Rc::new(Row {
                        key: (*key).into(),
                        cells: vec![Cell::Number((*value).into())],
                    })
                })
                .collect(),
        )
    }

    fn table_with(rows: Rc<Vec<Rc<Row>>>) -> Table {
        Table {
            columns: Vec::new(),
            rows,
            header: true,
            row_height: 36.0,
            selection: Selection::Single,
            selected: Vec::new(),
            sort: None,
            empty: None,
            follow_end: false,
            wrap: false,
            on_select: None,
            on_activate: None,
            on_sort: None,
            on_move: None,
        }
    }

    #[test]
    fn handlers_never_make_two_trees_differ() {
        let first = button("Test", ButtonStyle::Plain).on_press(Msg::ToggleDrawer);
        let second = button("Test", ButtonStyle::Plain).on_press(Msg::CloseDrawer);
        assert_eq!(first, second);
    }

    fn edit(removed: &[usize], inserted: &[usize], changed: &[usize]) -> KeyedChanges {
        KeyedChanges::Edit {
            removed: removed.to_vec(),
            inserted: inserted.to_vec(),
            changed: changed.to_vec(),
        }
    }

    #[test]
    fn row_changes_name_the_rows_to_redraw() {
        let old = table_with(rows(&[("a", "1"), ("b", "2")]));
        assert_eq!(
            table_with(old.rows.clone()).row_changes(&old),
            KeyedChanges::None
        );
        assert_eq!(
            table_with(rows(&[("a", "1"), ("b", "2")])).row_changes(&old),
            KeyedChanges::None
        );
        assert_eq!(
            table_with(rows(&[("a", "1"), ("b", "3")])).row_changes(&old),
            edit(&[], &[], &[1])
        );
    }

    #[test]
    fn rows_that_come_and_go_are_edits_while_the_rest_keep_their_order() {
        let old = table_with(rows(&[("a", "1"), ("b", "2"), ("c", "3")]));
        assert_eq!(
            table_with(rows(&[("new", "0"), ("a", "1"), ("b", "2"), ("c", "4")])).row_changes(&old),
            edit(&[], &[0], &[3]),
            "a new connection on top, an old one changed"
        );
        assert_eq!(
            table_with(rows(&[("d", "0"), ("a", "1"), ("c", "3")])).row_changes(&old),
            edit(&[1], &[0], &[])
        );
        assert_eq!(
            table_with(rows(&[])).row_changes(&old),
            edit(&[0, 1, 2], &[], &[])
        );
    }

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|key| (*key).into()).collect()
    }

    #[test]
    fn moved_rows_land_before_the_row_they_were_dropped_on_in_their_order() {
        let order = keys(&["a", "b", "c", "d", "e"]);
        assert_eq!(
            moved_order(&order, &keys(&["d"]), 1),
            keys(&["a", "d", "b", "c", "e"])
        );
        assert_eq!(
            moved_order(&order, &keys(&["a"]), 3),
            keys(&["b", "c", "a", "d", "e"])
        );
        assert_eq!(
            moved_order(&order, &keys(&["b"]), 5),
            keys(&["a", "c", "d", "e", "b"]),
            "to the end"
        );
        assert_eq!(
            moved_order(&order, &keys(&["e", "b"]), 0),
            keys(&["b", "e", "a", "c", "d"]),
            "several keep the order they had"
        );
        assert_eq!(
            moved_order(&order, &keys(&["b", "c"]), 2),
            order,
            "dropped on one of the moving rows"
        );
    }

    #[test]
    fn rows_that_change_order_reload() {
        let old = table_with(rows(&[("a", "1"), ("b", "2"), ("c", "3")]));
        assert_eq!(
            table_with(rows(&[("b", "2"), ("a", "1"), ("c", "3")])).row_changes(&old),
            KeyedChanges::Reload
        );
        assert_eq!(
            table_with(rows(&[("c", "3"), ("new", "0"), ("a", "1")])).row_changes(&old),
            KeyedChanges::Reload
        );
    }
}
