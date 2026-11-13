//! The table component as a `ListView` under a header row (WinUI has no
//! table control): the list virtualizes its rows, building containers only
//! for the rows it shows, and fills a container's cells when it comes into
//! view (`ContainerContentChanging`, "Optimize ListView and GridView").
//! Rows that come and go are inserted and removed from the list's items;
//! a changed row on screen takes its new content in place. Sorting,
//! selection and double clicks come back as interface events; changes the
//! interface makes itself (a new selection) are applied quietly so they do
//! not echo back.

use std::cell::{Cell as StdCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use windows_core::{EventRevoker, IInspectable, Interface, Result};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{
    Badge, Cell, Column, ColumnAlign, ColumnWidth, Image, KeyedChanges, Row, Selection,
    SortDirection, Table, TextStyle, Tone,
};
use egrio_ui::reconcile::NodeId;

use super::bindings::{
    BitmapImage, Button, ColumnDefinition, DataPackageOperation, DependencyObject, FontIcon,
    FrameworkElement, Grid, HorizontalAlignment, IButtonBase, IContentControl, IControl,
    IItemContainerMapping, IItemsControl, IListViewBase, IPanel, IRoutedEventArgs, IScrollViewer,
    ISelector, IUIElement, ListView, ListViewItem, ListViewSelectionMode, Orientation,
    RowDefinition, ScrollViewer, StackPanel, TextAlignment, TextBlock, TextTrimming, TextWrapping,
    UIElement, VerticalAlignment, Visibility, VisualTreeHelper,
};
use super::widgets::{badge_view, check, label, Post};
use super::xaml::{self, Element};

/// The space between two cells, and before the first and after the last.
const CELL_SPACING: f64 = 8.0;
const ROW_INSET: f64 = 8.0;

struct State {
    id: NodeId,
    post: Post,
    table: RefCell<Table>,
    /// Set while the interface itself changes the list.
    quiet: StdCell<bool>,
}

impl State {
    fn send(&self, event: Event) {
        (self.post)(UiEvent::Node { id: self.id, event });
    }
}

pub struct TableHost {
    root: Grid,
    header: Grid,
    list: ListView,
    empty: TextBlock,
    state: Rc<State>,
    header_events: RefCell<Vec<EventRevoker>>,
    _events: Vec<EventRevoker>,
}

/// A cell as it reads, for the test control channel's dump.
#[cfg(feature = "test-control")]
fn cell_text(cell: &egrio_ui::node::Cell) -> String {
    use egrio_ui::node::Cell;
    match cell {
        Cell::Text { text, .. } | Cell::Badge { text, .. } | Cell::Status { text, .. } => {
            text.clone()
        }
        Cell::Process { name, .. } => name.clone(),
        Cell::Number(text) => text.clone(),
        Cell::TwoLine {
            title,
            detail,
            trailing,
            ..
        } => [title.as_str(), detail.as_str(), trailing.as_str()]
            .iter()
            .filter(|part| !part.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" · "),
        Cell::Inline(cells) => cells.iter().map(cell_text).collect::<Vec<_>>().join(" "),
    }
}

#[cfg(feature = "test-control")]
/// What the test control channel drives a table by: its rows as shown, a
/// click's selection, a double click's activation and a drag's drop.
impl TableHost {
    /// The first `most` rows as their cells read, and how many there are.
    pub(super) fn shown(&self, most: usize) -> (Vec<String>, usize) {
        let table = self.state.table.borrow();
        let shown = table
            .rows
            .iter()
            .take(most)
            .map(|row| {
                row.cells
                    .iter()
                    .map(cell_text)
                    .filter(|text| !text.is_empty())
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .collect();
        (shown, table.rows.len())
    }

    pub(super) fn rows(&self) -> Vec<String> {
        self.state
            .table
            .borrow()
            .rows
            .iter()
            .map(|row| row.key.clone())
            .collect()
    }

    pub(super) fn select(&self, row: usize) -> Result<()> {
        self.list.cast::<ISelector>()?.SetSelectedIndex(row as i32)
    }

    pub(super) fn activate(&self, key: String) {
        self.state.send(Event::RowActivated(key));
    }

    pub(super) fn moved(&self, keys: Vec<String>, to: usize) {
        self.state.send(Event::RowsMoved { keys, to });
    }
}

impl TableHost {
    pub fn new(id: NodeId, props: &Table, post: Post) -> Result<Self> {
        let state = Rc::new(State {
            id,
            post,
            table: RefCell::new(props.clone()),
            quiet: StdCell::new(false),
        });
        let root = Grid::new()?;
        for length in [xaml::auto(), xaml::star()] {
            let row = RowDefinition::new()?;
            row.SetHeight(length)?;
            root.RowDefinitions()?.Append(&row)?;
        }
        let header = Grid::new()?;
        header.SetColumnSpacing(CELL_SPACING)?;
        header.SetPadding(xaml::thickness(ROW_INSET, 4.0))?;
        let list = ListView::new()?;
        Grid::SetRow(&list, 1)?;
        let empty = label("", TextStyle::Caption, Tone::Muted)?;
        Grid::SetRow(&empty, 1)?;
        let placed = empty.fe();
        placed.SetHorizontalAlignment(HorizontalAlignment::Center)?;
        placed.SetVerticalAlignment(VerticalAlignment::Center)?;
        empty.ui().SetIsHitTestVisible(false)?;
        let children = root.cast::<IPanel>()?.Children()?;
        children.Append(&header.cast::<UIElement>()?)?;
        children.Append(&list.cast::<UIElement>()?)?;
        children.Append(&empty.cast::<UIElement>()?)?;

        let items = list.cast::<IItemsControl>()?;
        items.SetItemTemplate(&xaml::empty_template("Grid")?)?;
        let fill = {
            let state = state.clone();
            list.cast::<IListViewBase>()?
                .ContainerContentChanging(move |_, args| {
                    let Ok(args) = args.ok() else { return };
                    if args.InRecycleQueue().unwrap_or(true) {
                        return;
                    }
                    let index = args.ItemIndex().unwrap_or(-1);
                    let table = state.table.borrow();
                    if let (Some(row), Ok(container)) = (
                        usize::try_from(index).ok().and_then(|i| table.rows.get(i)),
                        args.ItemContainer(),
                    ) {
                        if let Ok(grid) = container
                            .cast::<IContentControl>()
                            .and_then(|content| content.ContentTemplateRoot())
                            .and_then(|root| root.cast::<Grid>())
                        {
                            check(fill_row(&grid, &table, row), "fill a row");
                        }
                    }
                    let _ = args.SetHandled(true);
                })?
        };
        let selected = {
            let state = state.clone();
            let control = list.clone();
            list.cast::<ISelector>()?.SelectionChanged(move |_, _| {
                if state.quiet.get() {
                    return;
                }
                if let Ok(keys) = selected_keys(&control) {
                    state.send(Event::RowsSelected(keys));
                }
            })?
        };
        let activated = {
            let state = state.clone();
            let control = list.clone();
            list.ui().DoubleTapped(move |_, args| {
                // Only a double click on a row activates it: the empty
                // space under the rows is not the selected row.
                let on_row = args
                    .ok()
                    .ok()
                    .and_then(|args| args.cast::<IRoutedEventArgs>().ok())
                    .and_then(|args| args.OriginalSource().ok())
                    .is_some_and(|source| in_row(&source));
                if !on_row {
                    return;
                }
                if let Some(key) = selected_keys(&control)
                    .ok()
                    .and_then(|keys| keys.into_iter().next())
                {
                    state.send(Event::RowActivated(key));
                }
            })?
        };
        let moved = {
            let state = state.clone();
            let control = list.clone();
            list.cast::<IListViewBase>()?
                .DragItemsCompleted(move |_, args| {
                    let Ok(args) = args.ok() else { return };
                    if args.DropResult() != Ok(DataPackageOperation::Move) {
                        return;
                    }
                    let dragged: Vec<String> = args
                        .Items()
                        .map(|items| {
                            items
                                .into_iter()
                                .filter_map(|item| xaml::unboxed(&item))
                                .collect()
                        })
                        .unwrap_or_default();
                    check(rows_moved(&state, &control, dragged), "move rows");
                })?
        };
        let host = Self {
            root,
            header,
            list,
            empty,
            state,
            header_events: RefCell::new(Vec::new()),
            _events: vec![fill, selected, activated, moved],
        };
        host.configure(props, None)?;
        host.quietly(|| host.reload(props))?;
        host.apply_selection(props)?;
        if props.follow_end {
            host.scroll_to_end(props)?;
        }
        Ok(host)
    }

    pub fn element(&self) -> FrameworkElement {
        self.root.cast().expect("a grid is a framework element")
    }

    pub fn update(&self, props: &Table) -> Result<()> {
        let old = self.state.table.replace(props.clone());
        self.configure(props, Some(&old))?;
        let follow = props.follow_end && self.at_end();
        let items = self.list.cast::<IItemsControl>()?.Items()?;
        match props.row_changes(&old) {
            KeyedChanges::None => {}
            KeyedChanges::Edit {
                removed,
                inserted,
                changed,
            } => self.quietly(|| {
                for index in removed.iter().rev() {
                    items.RemoveAt(*index as u32)?;
                }
                for index in &inserted {
                    items.InsertAt(*index as u32, &xaml::boxed(&props.rows[*index].key)?)?;
                }
                // Rows off screen have no container and cost nothing.
                let mapping = self.list.cast::<IItemContainerMapping>()?;
                for index in changed {
                    let Ok(container) = mapping.ContainerFromIndex(index as i32) else {
                        continue;
                    };
                    if let Ok(grid) = container
                        .cast::<IContentControl>()
                        .and_then(|content| content.ContentTemplateRoot())
                        .and_then(|root| root.cast::<Grid>())
                    {
                        fill_row(&grid, props, &props.rows[index])?;
                    }
                }
                Ok(())
            })?,
            KeyedChanges::Reload => self.quietly(|| self.reload(props))?,
        }
        self.apply_selection(props)?;
        if follow {
            self.scroll_to_end(props)?;
        }
        Ok(())
    }

    fn reload(&self, props: &Table) -> Result<()> {
        keeping_offset(&self.list, || {
            let items = self.list.cast::<IItemsControl>()?.Items()?;
            items.Clear()?;
            for row in props.rows.iter() {
                items.Append(&xaml::boxed(&row.key)?)?;
            }
            Ok(())
        })
    }

    fn quietly(&self, change: impl FnOnce() -> Result<()>) -> Result<()> {
        let previous = self.state.quiet.replace(true);
        let result = change();
        self.state.quiet.set(previous);
        result
    }

    /// Columns, header, row height, selection mode and the empty text, where
    /// they differ from `old`.
    fn configure(&self, props: &Table, old: Option<&Table>) -> Result<()> {
        if old.is_none_or(|old| {
            old.columns != props.columns || old.sort != props.sort || old.header != props.header
        }) {
            self.build_header(props)?;
        }
        if old.is_none_or(|old| old.row_height != props.row_height) {
            self.list
                .cast::<IItemsControl>()?
                .SetItemContainerStyle(&xaml::style(
                    "ListViewItem",
                    Some("DefaultListViewItemStyle"),
                    &[
                        ("MinHeight", props.row_height.to_string()),
                        ("Padding", format!("{ROW_INSET},0,{ROW_INSET},0")),
                        ("HorizontalContentAlignment", "Stretch".into()),
                        ("VerticalContentAlignment", "Center".into()),
                    ],
                )?)?;
        }
        // Rows that can move are dragged within the list, which makes room
        // for them where they would land.
        let movable = props.on_move.is_some();
        if old.is_none_or(|old| old.on_move.is_some() != movable) {
            let list = self.list.cast::<IListViewBase>()?;
            list.SetCanDragItems(movable)?;
            list.SetCanReorderItems(movable)?;
            self.list.ui().SetAllowDrop(movable)?;
        }
        if old.is_none_or(|old| old.selection != props.selection) {
            self.list
                .cast::<IListViewBase>()?
                .SetSelectionMode(match props.selection {
                    Selection::None => ListViewSelectionMode::None,
                    Selection::Single => ListViewSelectionMode::Single,
                    Selection::Multiple => ListViewSelectionMode::Extended,
                })?;
        }
        let empty = props.rows.is_empty();
        self.empty.SetText(if empty {
            props.empty.as_deref().unwrap_or("")
        } else {
            ""
        })?;
        self.empty.ui().SetVisibility(if empty {
            Visibility::Visible
        } else {
            Visibility::Collapsed
        })
    }

    /// The column titles; a sortable one is a button that sorts by it, its
    /// arrow showing the direction.
    fn build_header(&self, props: &Table) -> Result<()> {
        set_columns(&self.header, &props.columns)?;
        let children = self.header.cast::<IPanel>()?.Children()?;
        children.Clear()?;
        let mut events = Vec::new();
        for (index, column) in props.columns.iter().enumerate() {
            let title = label(&column.title, TextStyle::Caption, Tone::Muted)?;
            let element: UIElement = if column.sortable {
                let line = StackPanel::new()?;
                line.SetOrientation(Orientation::Horizontal)?;
                line.SetSpacing(4.0)?;
                line.panel()
                    .Children()?
                    .Append(&title.cast::<UIElement>()?)?;
                if let Some((_, direction)) = props.sort.filter(|(sorted, _)| *sorted == index) {
                    let arrow = FontIcon::new()?;
                    arrow.fe().SetStyle(&xaml::icon_style(Tone::Muted, 10.0)?)?;
                    arrow.SetGlyph(match direction {
                        SortDirection::Ascending => "\u{E70E}",  // ChevronUp
                        SortDirection::Descending => "\u{E70D}", // ChevronDown
                    })?;
                    line.panel()
                        .Children()?
                        .Append(&arrow.cast::<UIElement>()?)?;
                }
                let button = Button::new()?;
                button
                    .fe()
                    .SetStyle(&xaml::resource::<super::bindings::Style>(
                        "SubtleButtonStyle",
                    )?)?;
                let control = button.cast::<IControl>()?;
                control.SetPadding(xaml::thickness(2.0, 2.0))?;
                button.cast::<IContentControl>()?.SetContent(&line)?;
                super::bindings::AutomationProperties::SetName(&button, &column.title)?;
                button.fe().SetHorizontalAlignment(match column.align {
                    ColumnAlign::Leading => HorizontalAlignment::Left,
                    ColumnAlign::Trailing => HorizontalAlignment::Right,
                })?;
                let state = self.state.clone();
                let ascending_first = column.align != ColumnAlign::Trailing;
                events.push(button.cast::<IButtonBase>()?.Click(move |_, _| {
                    let current = state.table.borrow().sort;
                    let direction = match current {
                        Some((sorted, SortDirection::Ascending)) if sorted == index => {
                            SortDirection::Descending
                        }
                        Some((sorted, SortDirection::Descending)) if sorted == index => {
                            SortDirection::Ascending
                        }
                        _ if ascending_first => SortDirection::Ascending,
                        _ => SortDirection::Descending,
                    };
                    state.send(Event::Sort(Some((index, direction))));
                })?);
                button.cast()?
            } else {
                if column.align == ColumnAlign::Trailing {
                    title.SetTextAlignment(TextAlignment::Right)?;
                }
                title.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
                title.cast()?
            };
            Grid::SetColumn(&xaml::as_element(&element)?, index as i32)?;
            children.Append(&element)?;
        }
        self.header.ui().SetVisibility(if props.header {
            Visibility::Visible
        } else {
            Visibility::Collapsed
        })?;
        *self.header_events.borrow_mut() = events;
        Ok(())
    }

    /// Selects the rows the interface names, if the list's own selection
    /// differs.
    fn apply_selection(&self, props: &Table) -> Result<()> {
        if props.selection == Selection::None {
            return Ok(());
        }
        let current = selected_keys(&self.list)?;
        let same = current.len() == props.selected.len()
            && current.iter().all(|key| props.selected.contains(key));
        if same {
            return Ok(());
        }
        let wanted: Vec<usize> = props
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| props.selected.contains(&row.key))
            .map(|(index, _)| index)
            .collect();
        self.quietly(|| {
            if props.selection == Selection::Single {
                return self
                    .list
                    .cast::<ISelector>()?
                    .SetSelectedIndex(wanted.first().map_or(-1, |index| *index as i32));
            }
            let items = self.list.cast::<IItemsControl>()?.Items()?;
            let selected = self.list.cast::<IListViewBase>()?.SelectedItems()?;
            selected.Clear()?;
            for index in wanted {
                selected.Append(&items.GetAt(index as u32)?)?;
            }
            Ok(())
        })
    }

    /// Whether the list shows its last rows, give or take two rows.
    fn at_end(&self) -> bool {
        let Some(scroll) = scroll_viewer(&self.list.cast().ok()) else {
            return true;
        };
        let row = self.state.table.borrow().row_height;
        match (scroll.VerticalOffset(), scroll.ScrollableHeight()) {
            (Ok(offset), Ok(height)) => offset >= height - 2.0 * row,
            _ => true,
        }
    }

    fn scroll_to_end(&self, props: &Table) -> Result<()> {
        let items = self.list.cast::<IItemsControl>()?.Items()?;
        let count = items.Size()?;
        if count > 0 && !props.rows.is_empty() {
            self.list
                .cast::<IListViewBase>()?
                .ScrollIntoView(&items.GetAt(count - 1)?)?;
        }
        Ok(())
    }
}

/// Reports rows the list reordered itself as moved before the row at the
/// gap they landed in, counted in the order the interface gave, and takes
/// the new order as the shown one, so the interface's matching order
/// changes nothing on screen (and a refused move puts the rows back).
fn rows_moved(state: &State, list: &ListView, dragged: Vec<String>) -> Result<()> {
    if dragged.is_empty() {
        return Ok(());
    }
    let items = list.cast::<IItemsControl>()?.Items()?;
    let order: Vec<String> = (0..items.Size()?)
        .filter_map(|index| items.GetAt(index).ok())
        .filter_map(|item| xaml::unboxed(&item))
        .collect();
    let mut table = state.table.borrow_mut();
    let before: Vec<String> = table.rows.iter().map(|row| row.key.clone()).collect();
    let Some(to) = landing(&before, &order, &dragged) else {
        return Ok(());
    };
    let keys: Vec<String> = before
        .iter()
        .filter(|key| dragged.contains(key))
        .cloned()
        .collect();
    let mut rows: Vec<_> = table.rows.iter().cloned().collect();
    rows.sort_by_key(|row| order.iter().position(|key| *key == row.key));
    table.rows = Rc::new(rows);
    drop(table);
    state.send(Event::RowsMoved { keys, to });
    Ok(())
}

/// Where dragged rows landed: the index, in `before`, of the first row after
/// them in `after` that was not dragged, or the end; `None` when they did
/// not move.
fn landing(before: &[String], after: &[String], dragged: &[String]) -> Option<usize> {
    if before == after {
        return None;
    }
    let first = after.iter().position(|key| dragged.contains(key))?;
    let next = after[first..].iter().find(|key| !dragged.contains(key));
    Some(next.map_or(before.len(), |key| {
        before
            .iter()
            .position(|other| other == key)
            .unwrap_or(before.len())
    }))
}

/// Refills a list in `change` and keeps it scrolled where it was, as a list
/// whose content changes in place would stay: the list lays its new items
/// out at once and scrolls back before it draws.
pub fn keeping_offset(list: &impl Interface, change: impl FnOnce() -> Result<()>) -> Result<()> {
    let scroll = scroll_viewer(&list.cast().ok());
    let offset = scroll
        .as_ref()
        .and_then(|scroll| scroll.VerticalOffset().ok())
        .filter(|offset| *offset > 0.0);
    change()?;
    if let (Some(scroll), Some(offset)) = (scroll, offset) {
        list.cast::<IUIElement>()?.UpdateLayout()?;
        scroll.ChangeViewWithOptionalAnimation(None, Some(offset), None, true)?;
    }
    Ok(())
}

/// The list's own scroll viewer, inside its template.
fn scroll_viewer(element: &Option<super::bindings::DependencyObject>) -> Option<IScrollViewer> {
    let element = element.as_ref()?;
    if let Ok(scroll) = element.cast::<ScrollViewer>() {
        return scroll.cast().ok();
    }
    let count = VisualTreeHelper::GetChildrenCount(element).ok()?;
    (0..count).find_map(|index| scroll_viewer(&VisualTreeHelper::GetChild(element, index).ok()))
}

fn selected_keys(list: &ListView) -> Result<Vec<String>> {
    let selected = list.cast::<IListViewBase>()?.SelectedItems()?;
    Ok((0..selected.Size()?)
        .filter_map(|index| selected.GetAt(index).ok())
        .filter_map(|item| xaml::unboxed(&item))
        .collect())
}

fn set_columns(grid: &Grid, columns: &[Column]) -> Result<()> {
    let definitions = grid.ColumnDefinitions()?;
    definitions.Clear()?;
    for column in columns {
        let definition = ColumnDefinition::new()?;
        match column.width {
            ColumnWidth::Fixed(width) => definition.SetWidth(xaml::pixels(width))?,
            ColumnWidth::Flexible { min } => {
                definition.SetWidth(xaml::star())?;
                definition.SetMinWidth(min)?;
            }
        }
        definitions.Append(&definition)?;
    }
    Ok(())
}

/// Gives a row's container this row's cells.
fn fill_row(grid: &Grid, table: &Table, row: &Row) -> Result<()> {
    if grid.ColumnDefinitions()?.Size()? as usize != table.columns.len() {
        set_columns(grid, &table.columns)?;
        grid.SetColumnSpacing(CELL_SPACING)?;
    }
    let children = grid.cast::<IPanel>()?.Children()?;
    children.Clear()?;
    for (index, cell) in row.cells.iter().enumerate().take(table.columns.len()) {
        let align = table.columns[index].align;
        let element = cell_view(cell, align, table.wrap)?;
        Grid::SetColumn(&xaml::as_element(&element)?, index as i32)?;
        children.Append(&element)?;
    }
    Ok(())
}

/// Whether what was clicked is inside one of the list's rows.
fn in_row(source: &IInspectable) -> bool {
    let Ok(mut element) = source.cast::<DependencyObject>() else {
        return false;
    };
    loop {
        if element.cast::<ListViewItem>().is_ok() {
            return true;
        }
        match VisualTreeHelper::GetParent(&element) {
            Ok(parent) => element = parent,
            Err(_) => return false,
        }
    }
}

fn text_cell(
    value: &str,
    style: TextStyle,
    tone: Tone,
    align: ColumnAlign,
    wrap: bool,
) -> Result<TextBlock> {
    let block = label(value, style, tone)?;
    if wrap {
        block.SetTextWrapping(TextWrapping::Wrap)?;
        block.SetTextTrimming(TextTrimming::None)?;
        block.SetIsTextSelectionEnabled(true)?;
    }
    if align == ColumnAlign::Trailing {
        block.SetTextAlignment(TextAlignment::Right)?;
    }
    block.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
    Ok(block)
}

fn line(spacing: f64) -> Result<StackPanel> {
    let panel = StackPanel::new()?;
    panel.SetOrientation(Orientation::Horizontal)?;
    panel.SetSpacing(spacing)?;
    panel.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
    Ok(panel)
}

fn glyph(text: &str, tone: Tone, size: f64) -> Result<FontIcon> {
    let icon = FontIcon::new()?;
    icon.fe().SetStyle(&xaml::icon_style(tone, size)?)?;
    icon.SetGlyph(text)?;
    icon.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
    Ok(icon)
}

/// An app icon, or the fallback symbol without one.
fn picture(image: Option<&Image>, fallback: egrio_ui::node::Icon) -> Result<UIElement> {
    if let Some(source) = image.and_then(|image| decoded(image).ok()) {
        let view = super::bindings::Image::new()?;
        view.SetSource(&source)?;
        view.fe().SetWidth(16.0)?;
        view.fe().SetHeight(16.0)?;
        return view.cast();
    }
    glyph(xaml::glyph(fallback), Tone::Muted, 16.0)?.cast()
}

fn cell_view(cell: &Cell, align: ColumnAlign, wrap: bool) -> Result<UIElement> {
    Ok(match cell {
        Cell::Text { text, tone, mono } => text_cell(
            text,
            if *mono {
                TextStyle::Mono
            } else {
                TextStyle::Body
            },
            *tone,
            align,
            wrap,
        )?
        .cast()?,
        Cell::Number(value) => {
            let block = text_cell(
                value,
                TextStyle::Caption,
                Tone::Muted,
                ColumnAlign::Trailing,
                false,
            )?;
            xaml::tabular_figures(&block)?;
            block.cast()?
        }
        Cell::Badge { text, tone } => {
            let (surface, _) = badge_view(&Badge {
                text: text.clone(),
                tone: *tone,
            })?;
            surface
                .fe()
                .SetHorizontalAlignment(HorizontalAlignment::Left)?;
            surface.cast()?
        }
        Cell::Status { text, tone } => {
            let panel = line(6.0)?;
            // CircleFill, small.
            panel
                .panel()
                .Children()?
                .Append(&glyph("\u{EA3B}", *tone, 8.0)?.cast::<UIElement>()?)?;
            panel.panel().Children()?.Append(
                &text_cell(text, TextStyle::Body, *tone, ColumnAlign::Leading, false)?
                    .cast::<UIElement>()?,
            )?;
            panel.cast()?
        }
        Cell::Process { name, icon } => {
            let panel = line(6.0)?;
            panel
                .panel()
                .Children()?
                .Append(&picture(icon.as_ref(), egrio_ui::node::Icon::App)?)?;
            panel.panel().Children()?.Append(
                &text_cell(
                    name,
                    TextStyle::Body,
                    Tone::Default,
                    ColumnAlign::Leading,
                    false,
                )?
                .cast::<UIElement>()?,
            )?;
            panel.cast()?
        }
        Cell::TwoLine {
            title,
            detail,
            icon,
            fallback,
            trailing,
            trailing_tone,
        } => {
            let grid = Grid::new()?;
            grid.SetColumnSpacing(8.0)?;
            for length in [xaml::auto(), xaml::star(), xaml::auto()] {
                let column = ColumnDefinition::new()?;
                column.SetWidth(length)?;
                grid.ColumnDefinitions()?.Append(&column)?;
            }
            let image = picture(icon.as_ref(), *fallback)?;
            image
                .cast::<super::bindings::IFrameworkElement>()?
                .SetVerticalAlignment(VerticalAlignment::Center)?;
            let lines = StackPanel::new()?;
            lines.SetSpacing(1.0)?;
            lines.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
            lines
                .panel()
                .Children()?
                .Append(&label(title, TextStyle::Body, Tone::Default)?.cast::<UIElement>()?)?;
            lines
                .panel()
                .Children()?
                .Append(&label(detail, TextStyle::Caption, Tone::Muted)?.cast::<UIElement>()?)?;
            Grid::SetColumn(&lines, 1)?;
            let figure = text_cell(
                trailing,
                TextStyle::Caption,
                *trailing_tone,
                ColumnAlign::Trailing,
                false,
            )?;
            Grid::SetColumn(&figure, 2)?;
            let children = grid.cast::<IPanel>()?.Children()?;
            children.Append(&image)?;
            children.Append(&lines.cast::<UIElement>()?)?;
            children.Append(&figure.cast::<UIElement>()?)?;
            grid.cast()?
        }
        Cell::Inline(cells) => {
            // The first cell in a star column, cut where its tags start; the
            // tags in columns of their own size, at the column's end.
            let grid = Grid::new()?;
            grid.SetColumnSpacing(6.0)?;
            let children = grid.cast::<IPanel>()?.Children()?;
            for (index, cell) in cells.iter().enumerate() {
                let column = ColumnDefinition::new()?;
                column.SetWidth(if index == 0 {
                    xaml::star()
                } else {
                    xaml::auto()
                })?;
                grid.ColumnDefinitions()?.Append(&column)?;
                let view = cell_view(cell, ColumnAlign::Leading, wrap)?;
                Grid::SetColumn(&xaml::as_element(&view)?, index as i32)?;
                children.Append(&view)?;
            }
            grid.cast()?
        }
    })
}

thread_local! {
    /// Decoded app icons, by the identity of their PNG data.
    static IMAGES: RefCell<HashMap<usize, BitmapImage>> = RefCell::new(HashMap::new());
}

fn decoded(image: &Image) -> Result<BitmapImage> {
    let key = Arc::as_ptr(&image.0) as *const u8 as usize;
    if let Some(bitmap) = IMAGES.with(|images| images.borrow().get(&key).cloned()) {
        return Ok(bitmap);
    }
    let bitmap = super::images::bitmap(&image.0)?;
    IMAGES.with(|images| images.borrow_mut().insert(key, bitmap.clone()));
    Ok(bitmap)
}

#[cfg(test)]
mod tests {
    use super::landing;

    fn keys(text: &str) -> Vec<String> {
        text.chars().map(String::from).collect()
    }

    #[test]
    fn dropped_rows_land_before_the_next_row_they_did_not_carry() {
        let before = keys("abcd");
        assert_eq!(landing(&before, &keys("acdb"), &keys("b")), Some(4));
        assert_eq!(landing(&before, &keys("dabc"), &keys("d")), Some(0));
        assert_eq!(landing(&before, &keys("bcad"), &keys("a")), Some(3));
        assert_eq!(landing(&before, &keys("cabd"), &keys("ab")), Some(3));
        assert_eq!(landing(&before, &keys("abcd"), &keys("b")), None);
    }
}
