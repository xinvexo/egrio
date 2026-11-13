//! The table component: a `GtkColumnView` for a table with a header, a
//! `GtkListView` for a list without one. Both build widgets only for the
//! rows they show ("List Widget Overview" in the GTK documentation). The
//! model holds each row's key; a row's cells come from the interface's rows
//! when GTK binds the row to a widget. Rows that come and go are spliced
//! into the model, and a changed row on screen takes its new content in
//! place. Sorting, selection, double clicks and dragged rows come back as
//! interface events; changes the interface makes itself (a new selection,
//! the sort) are applied quietly so they do not echo back.

use std::cell::{Cell as StdCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::{Rc, Weak};

use gtk::prelude::*;
use gtk::{gdk, gio, glib};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{
    ColumnAlign, ColumnWidth, KeyedChanges, Row, Selection, SortDirection, Table, TextStyle, Tone,
};
use egrio_ui::reconcile::NodeId;

use super::cells::CellView;
use super::style;
use super::widgets::Post;

/// The space between two cells of a list's row.
const CELL_SPACING: i32 = 8;

struct State {
    id: NodeId,
    post: Post,
    table: RefCell<Table>,
    /// Each row's place among the interface's rows, by key.
    places: RefCell<HashMap<String, usize>>,
    store: gio::ListStore,
    selection: RefCell<gtk::SelectionModel>,
    /// Set while the interface itself changes the view.
    quiet: StdCell<bool>,
    /// The widgets showing each row now: a cell of a table's row, or a
    /// list's whole row.
    bound: RefCell<HashMap<String, Vec<glib::WeakRef<gtk::Widget>>>>,
    /// The row a dragged row would be dropped beside, and whether before it.
    drop_mark: RefCell<Option<(String, bool)>>,
}

impl State {
    fn send(&self, event: Event) {
        (self.post)(UiEvent::Node { id: self.id, event });
    }

    fn quietly(&self, change: impl FnOnce()) {
        let previous = self.quiet.replace(true);
        change();
        self.quiet.set(previous);
    }

    fn key_at(&self, position: u32) -> Option<String> {
        key_of(&self.store.item(position)?)
    }

    fn selected_keys(&self) -> Vec<String> {
        let selection = self.selection.borrow().selection();
        (0..selection.size() as u32)
            .filter_map(|index| self.key_at(selection.nth(index)))
            .collect()
    }

    /// Draws a bound widget with the current content of its row.
    fn render(&self, widget: &gtk::Widget, key: &str) {
        let table = self.table.borrow();
        let Some(row) = self
            .places
            .borrow()
            .get(key)
            .and_then(|place| table.rows.get(*place))
        else {
            return;
        };
        render(widget, &table, row);
    }

    fn bind(&self, widget: &gtk::Widget, key: &str) {
        self.bound
            .borrow_mut()
            .entry(key.to_owned())
            .or_default()
            .push(widget.downgrade());
        self.render(widget, key);
        mark_drop(widget, self.drop_mark.borrow().as_ref(), key);
    }

    fn unbind(&self, widget: &gtk::Widget, key: &str) {
        let mut bound = self.bound.borrow_mut();
        if let Some(widgets) = bound.get_mut(key) {
            widgets.retain(|weak| weak.upgrade().is_some_and(|other| &other != widget));
            if widgets.is_empty() {
                bound.remove(key);
            }
        }
        mark_drop(widget, None, key);
    }

    /// Shows where dragged rows would land: a line above or below a row.
    fn set_drop_mark(&self, mark: Option<(String, bool)>) {
        let old = self.drop_mark.replace(mark.clone());
        if old == mark {
            return;
        }
        let bound = self.bound.borrow();
        for key in old.iter().chain(mark.iter()).map(|(key, _)| key) {
            for widget in bound.get(key).into_iter().flatten() {
                if let Some(widget) = widget.upgrade() {
                    mark_drop(&widget, mark.as_ref(), key);
                }
            }
        }
    }
}

fn key_of(object: &glib::Object) -> Option<String> {
    let boxed = object.downcast_ref::<glib::BoxedAnyObject>()?;
    let key = boxed.borrow::<String>();
    Some(key.clone())
}

fn row_object(key: &str) -> glib::BoxedAnyObject {
    glib::BoxedAnyObject::new(key.to_owned())
}

fn mark_drop(widget: &gtk::Widget, mark: Option<&(String, bool)>, key: &str) {
    let (above, below) = match mark {
        Some((marked, before)) if marked == key => (*before, !*before),
        _ => (false, false),
    };
    for (class, wanted) in [("egrio-drop-above", above), ("egrio-drop-below", below)] {
        if wanted {
            widget.add_css_class(class);
        } else {
            widget.remove_css_class(class);
        }
    }
}

/// Draws a table cell or a list row from `row`.
fn render(widget: &gtk::Widget, table: &Table, row: &Row) {
    let cells: Vec<CellView> = match widget.downcast_ref::<CellView>() {
        Some(cell) => vec![cell.clone()],
        None => {
            let mut cells = Vec::new();
            let mut child = widget.first_child();
            while let Some(widget) = child {
                child = widget.next_sibling();
                if let Ok(cell) = widget.downcast::<CellView>() {
                    cells.push(cell);
                }
            }
            cells
        }
    };
    for cell in cells {
        let column = cell.column();
        if let (Some(content), Some(spec)) = (row.cells.get(column), table.columns.get(column)) {
            cell.render(content, spec.align, table.wrap);
        }
    }
}

enum View {
    Columns {
        view: gtk::ColumnView,
        columns: Vec<gtk::ColumnViewColumn>,
    },
    List(gtk::ListView),
}

pub struct TableHost {
    root: gtk::Overlay,
    scroll: gtk::ScrolledWindow,
    /// Built again when the columns, the header or the row height change.
    view: RefCell<View>,
    empty: gtk::Label,
    state: Rc<State>,
}

/// The view for a table's columns, header and row height, in `scroll`.
fn build_view(
    state: &Rc<State>,
    props: &Table,
    selection: &gtk::SelectionModel,
    scroll: &gtk::ScrolledWindow,
) -> View {
    let view = if props.header {
        scroll.set_policy(gtk::PolicyType::Automatic, gtk::PolicyType::Automatic);
        column_view(state, props, selection)
    } else {
        scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        list_view(state, props, selection)
    };
    match &view {
        View::Columns { view, .. } => scroll.set_child(Some(view)),
        View::List(view) => scroll.set_child(Some(view)),
    }
    view
}

impl TableHost {
    pub fn new(id: NodeId, props: &Table, post: Post) -> Self {
        let store = gio::ListStore::new::<glib::BoxedAnyObject>();
        let selection = selection_model(props.selection, &store);
        let state = Rc::new(State {
            id,
            post,
            table: RefCell::new(props.clone()),
            places: RefCell::new(HashMap::new()),
            store,
            selection: RefCell::new(selection.clone()),
            quiet: StdCell::new(false),
            bound: RefCell::new(HashMap::new()),
            drop_mark: RefCell::new(None),
        });
        watch_selection(&state, &selection);
        let scroll = gtk::ScrolledWindow::new();
        let view = RefCell::new(build_view(&state, props, &selection, &scroll));
        let empty = style::label("", TextStyle::Body, Tone::Muted);
        empty.set_halign(gtk::Align::Center);
        empty.set_valign(gtk::Align::Center);
        empty.set_can_target(false);
        let root = gtk::Overlay::new();
        root.set_child(Some(&scroll));
        root.add_overlay(&empty);
        let host = Self {
            root,
            scroll,
            view,
            empty,
            state,
        };
        host.state.quietly(|| host.reload(props));
        host.apply_sort(props);
        host.apply_selection(props);
        host.show_empty(props);
        if props.follow_end {
            host.scroll_to_end();
        }
        host
    }

    pub fn widget(&self) -> gtk::Widget {
        self.root.clone().upcast()
    }

    pub fn update(&self, props: &Table) {
        let old = self.state.table.replace(props.clone());
        let follow = props.follow_end && self.at_end(&old);
        if old.selection != props.selection {
            let selection = selection_model(props.selection, &self.state.store);
            watch_selection(&self.state, &selection);
            match &*self.view.borrow() {
                View::Columns { view, .. } => view.set_model(Some(&selection)),
                View::List(view) => view.set_model(Some(&selection)),
            }
            *self.state.selection.borrow_mut() = selection;
        }
        // New columns, a header that comes or goes or another row height
        // make a new view, whose rows draw themselves as they show.
        let rebuilt = old.columns != props.columns
            || old.header != props.header
            || old.row_height != props.row_height;
        if rebuilt {
            self.state.bound.borrow_mut().clear();
            let selection = self.state.selection.borrow().clone();
            *self.view.borrow_mut() = build_view(&self.state, props, &selection, &self.scroll);
        }
        match props.row_changes(&old) {
            KeyedChanges::None => {}
            KeyedChanges::Edit {
                removed,
                inserted,
                changed,
            } => {
                self.index(props);
                self.state.quietly(|| {
                    for index in removed.iter().rev() {
                        self.state.store.remove(*index as u32);
                    }
                    for index in &inserted {
                        self.state
                            .store
                            .insert(*index as u32, &row_object(&props.rows[*index].key));
                    }
                });
                // Rows off screen have no widgets and cost nothing.
                let bound = self.state.bound.borrow().clone();
                for index in changed {
                    let key = &props.rows[index].key;
                    for widget in bound.get(key).into_iter().flatten() {
                        if let Some(widget) = widget.upgrade() {
                            self.state.render(&widget, key);
                        }
                    }
                }
            }
            KeyedChanges::Reload => self.state.quietly(|| self.reload(props)),
        }
        if old.wrap != props.wrap && !rebuilt {
            self.redraw_bound();
        }
        if old.sort != props.sort || rebuilt {
            self.apply_sort(props);
        }
        self.apply_selection(props);
        self.show_empty(props);
        if follow {
            self.scroll_to_end();
        }
    }

    fn index(&self, props: &Table) {
        *self.state.places.borrow_mut() = props
            .rows
            .iter()
            .enumerate()
            .map(|(place, row)| (row.key.clone(), place))
            .collect();
    }

    fn reload(&self, props: &Table) {
        self.index(props);
        let rows: Vec<glib::BoxedAnyObject> =
            props.rows.iter().map(|row| row_object(&row.key)).collect();
        self.state
            .store
            .splice(0, self.state.store.n_items(), &rows);
    }

    fn redraw_bound(&self) {
        let bound = self.state.bound.borrow().clone();
        for (key, widgets) in bound {
            for widget in widgets.iter().filter_map(glib::WeakRef::upgrade) {
                self.state.render(&widget, &key);
            }
        }
    }

    fn apply_sort(&self, props: &Table) {
        let shown = self.view.borrow();
        let View::Columns { view, columns } = &*shown else {
            return;
        };
        self.state.quietly(|| match props.sort {
            Some((index, direction)) => view.sort_by_column(
                columns.get(index),
                match direction {
                    SortDirection::Ascending => gtk::SortType::Ascending,
                    SortDirection::Descending => gtk::SortType::Descending,
                },
            ),
            None => view.sort_by_column(None, gtk::SortType::Ascending),
        });
    }

    /// Selects the rows the interface names, if the view's own selection
    /// differs.
    fn apply_selection(&self, props: &Table) {
        if props.selection == Selection::None {
            return;
        }
        let current: HashSet<String> = self.state.selected_keys().into_iter().collect();
        let wanted: HashSet<String> = props.selected.iter().cloned().collect();
        if current == wanted {
            return;
        }
        let places = self.state.places.borrow();
        let selected = gtk::Bitset::new_empty();
        for key in &props.selected {
            if let Some(place) = places.get(key) {
                selected.add(*place as u32);
            }
        }
        let all = gtk::Bitset::new_range(0, self.state.store.n_items());
        let model = self.state.selection.borrow().clone();
        self.state
            .quietly(|| match model.downcast_ref::<gtk::SingleSelection>() {
                Some(single) => single.set_selected(match selected.size() {
                    0 => gtk::INVALID_LIST_POSITION,
                    _ => selected.nth(0),
                }),
                None => {
                    model.set_selection(&selected, &all);
                }
            });
    }

    fn show_empty(&self, props: &Table) {
        let empty = props.rows.is_empty();
        self.empty
            .set_text(props.empty.as_deref().filter(|_| empty).unwrap_or(""));
        self.empty.set_visible(empty && props.empty.is_some());
    }

    /// Whether the view shows its last rows, give or take two rows.
    fn at_end(&self, old: &Table) -> bool {
        let adjustment = self.scroll.vadjustment();
        adjustment.value() >= adjustment.upper() - adjustment.page_size() - 2.0 * old.row_height
    }

    fn scroll_to_end(&self) {
        let count = self.state.store.n_items();
        if count == 0 {
            return;
        }
        match &*self.view.borrow() {
            View::Columns { view, .. } => {
                view.scroll_to(count - 1, None, gtk::ListScrollFlags::NONE, None)
            }
            View::List(view) => view.scroll_to(count - 1, gtk::ListScrollFlags::NONE, None),
        }
    }
}

fn selection_model(selection: Selection, store: &gio::ListStore) -> gtk::SelectionModel {
    match selection {
        Selection::None => gtk::NoSelection::new(Some(store.clone())).upcast(),
        Selection::Single => {
            let single = gtk::SingleSelection::new(Some(store.clone()));
            single.set_autoselect(false);
            single.set_can_unselect(true);
            single.upcast()
        }
        Selection::Multiple => gtk::MultiSelection::new(Some(store.clone())).upcast(),
    }
}

fn watch_selection(state: &Rc<State>, selection: &gtk::SelectionModel) {
    let weak = Rc::downgrade(state);
    selection.connect_selection_changed(move |_, _, _| {
        let Some(state) = weak.upgrade() else { return };
        if !state.quiet.get() {
            state.send(Event::RowsSelected(state.selected_keys()));
        }
    });
}

fn column_view(state: &Rc<State>, props: &Table, selection: &gtk::SelectionModel) -> View {
    let view = gtk::ColumnView::new(Some(selection.clone()));
    view.add_css_class("data-table");
    view.add_css_class("egrio-table");
    view.set_reorderable(false);
    view.set_show_row_separators(false);
    view.set_show_column_separators(false);
    let mut columns = Vec::new();
    for (index, spec) in props.columns.iter().enumerate() {
        let factory = factory(state, Some(index));
        let column = gtk::ColumnViewColumn::new(Some(&spec.title), Some(factory));
        match spec.width {
            ColumnWidth::Fixed(width) => column.set_fixed_width(width.round() as i32),
            ColumnWidth::Flexible { min } => {
                column.set_fixed_width(min.round() as i32);
                column.set_expand(true);
            }
        }
        column.set_resizable(false);
        if spec.sortable {
            // The interface sorts the rows; the sorter only marks the
            // column the user chose.
            column.set_sorter(Some(&gtk::CustomSorter::new(|_, _| gtk::Ordering::Equal)));
        }
        view.append_column(&column);
        columns.push(column);
    }
    if let Some(sorter) = view.sorter() {
        let weak = Rc::downgrade(state);
        let columns = columns.clone();
        sorter.connect_changed(move |sorter, _| {
            let Some(state) = weak.upgrade() else { return };
            if state.quiet.get() {
                return;
            }
            let Some(sorter) = sorter.downcast_ref::<gtk::ColumnViewSorter>() else {
                return;
            };
            let chosen = sorter
                .primary_sort_column()
                .and_then(|column| columns.iter().position(|candidate| *candidate == column));
            let sort = chosen.map(|index| {
                let table = state.table.borrow();
                // A newly chosen column of figures sorts largest first.
                let new = table.sort.is_none_or(|(sorted, _)| sorted != index);
                let trailing = table.columns[index].align == ColumnAlign::Trailing;
                let direction = if new && trailing {
                    SortDirection::Descending
                } else {
                    match sorter.primary_sort_order() {
                        gtk::SortType::Descending => SortDirection::Descending,
                        _ => SortDirection::Ascending,
                    }
                };
                (index, direction)
            });
            state.send(Event::Sort(sort));
        });
    }
    {
        let weak = Rc::downgrade(state);
        view.connect_activate(move |_, position| {
            let Some(state) = weak.upgrade() else { return };
            if let Some(key) = state.key_at(position) {
                state.send(Event::RowActivated(key));
            }
        });
    }
    View::Columns { view, columns }
}

fn list_view(state: &Rc<State>, props: &Table, selection: &gtk::SelectionModel) -> View {
    let view = gtk::ListView::new(Some(selection.clone()), Some(factory(state, None)));
    if props.selection == Selection::None {
        view.add_css_class("egrio-list");
    } else {
        view.add_css_class("navigation-sidebar");
    }
    let weak = Rc::downgrade(state);
    view.connect_activate(move |_, position| {
        let Some(state) = weak.upgrade() else { return };
        if let Some(key) = state.key_at(position) {
            state.send(Event::RowActivated(key));
        }
    });
    View::List(view)
}

/// The factory for one column's cells, or for a list's whole rows.
fn factory(state: &Rc<State>, column: Option<usize>) -> gtk::SignalListItemFactory {
    let factory = gtk::SignalListItemFactory::new();
    {
        let weak = Rc::downgrade(state);
        factory.connect_setup(move |_, item| {
            let (Some(state), Some(item)) = (weak.upgrade(), item.downcast_ref::<gtk::ListItem>())
            else {
                return;
            };
            let widget: gtk::Widget = match column {
                Some(column) => {
                    let cell = CellView::new(column);
                    cell.set_item(item);
                    cell.upcast()
                }
                None => list_row(&state.table.borrow(), item).upcast(),
            };
            widget.set_size_request(-1, state.table.borrow().row_height.round() as i32);
            reorderable(&weak, &widget, item);
            item.set_child(Some(&widget));
        });
    }
    {
        let weak = Rc::downgrade(state);
        factory.connect_bind(move |_, item| {
            let (Some(state), Some(item)) = (weak.upgrade(), item.downcast_ref::<gtk::ListItem>())
            else {
                return;
            };
            if let (Some(widget), Some(key)) = (item.child(), item.item().and_then(|o| key_of(&o)))
            {
                state.bind(&widget, &key);
            }
        });
    }
    {
        let weak = Rc::downgrade(state);
        factory.connect_unbind(move |_, item| {
            let (Some(state), Some(item)) = (weak.upgrade(), item.downcast_ref::<gtk::ListItem>())
            else {
                return;
            };
            if let (Some(widget), Some(key)) = (item.child(), item.item().and_then(|o| key_of(&o)))
            {
                state.unbind(&widget, &key);
            }
        });
    }
    factory
}

/// A list's row: one cell per column, the fixed ones at their width and the
/// flexible ones sharing the rest.
fn list_row(table: &Table, item: &gtk::ListItem) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, CELL_SPACING);
    for (index, spec) in table.columns.iter().enumerate() {
        let cell = CellView::new(index);
        cell.set_item(item);
        match spec.width {
            ColumnWidth::Fixed(width) => {
                cell.set_size_request(width.round() as i32, -1);
                cell.set_hexpand(false);
            }
            ColumnWidth::Flexible { min } => {
                cell.set_size_request(min.round() as i32, -1);
                cell.set_hexpand(true);
            }
        }
        row.append(&cell);
    }
    row
}

/// Lets a row's widget be dragged to another place and take dropped rows,
/// while the table's rows can move: it carries the keys of the rows it
/// moves, the selected ones when it is one of them.
fn reorderable(state: &Weak<State>, widget: &gtk::Widget, item: &gtk::ListItem) {
    let source = gtk::DragSource::new();
    source.set_actions(gdk::DragAction::MOVE);
    {
        let state = state.clone();
        let item = item.downgrade();
        source.connect_prepare(move |_, _, _| {
            let state = state.upgrade()?;
            state.table.borrow().on_move.as_ref()?;
            let key = item.upgrade()?.item().and_then(|object| key_of(&object))?;
            let selected = state.selected_keys();
            let keys = if selected.contains(&key) {
                selected
            } else {
                vec![key]
            };
            Some(gdk::ContentProvider::for_value(&keys.join("\n").to_value()))
        });
    }
    {
        let widget = widget.downgrade();
        source.connect_drag_begin(move |source, _| {
            if let Some(widget) = widget.upgrade() {
                source.set_icon(Some(&gtk::WidgetPaintable::new(Some(&widget))), 0, 0);
            }
        });
    }
    widget.add_controller(source);

    let target = gtk::DropTarget::new(glib::Type::STRING, gdk::DragAction::MOVE);
    let place = {
        let state = state.clone();
        let item = item.downgrade();
        let widget = widget.downgrade();
        move |y: f64| -> Option<(Rc<State>, String, u32, bool)> {
            let state = state.upgrade()?;
            state.table.borrow().on_move.as_ref()?;
            let item = item.upgrade()?;
            let key = item.item().and_then(|object| key_of(&object))?;
            let before = y < f64::from(widget.upgrade()?.height()) / 2.0;
            Some((state, key, item.position(), before))
        }
    };
    {
        let place = place.clone();
        target.connect_motion(move |_, _, y| match place(y) {
            Some((state, key, _, before)) => {
                state.set_drop_mark(Some((key, before)));
                gdk::DragAction::MOVE
            }
            None => gdk::DragAction::empty(),
        });
    }
    {
        let state = state.clone();
        target.connect_leave(move |_| {
            if let Some(state) = state.upgrade() {
                state.set_drop_mark(None);
            }
        });
    }
    target.connect_drop(move |_, value, _, y| {
        let Some((state, _, position, before)) = place(y) else {
            return false;
        };
        state.set_drop_mark(None);
        let Ok(text) = value.get::<String>() else {
            return false;
        };
        let keys: Vec<String> = text.split('\n').map(str::to_owned).collect();
        // Only this table's rows move.
        if !keys
            .iter()
            .all(|key| state.places.borrow().contains_key(key))
        {
            return false;
        }
        let to = if before { position } else { position + 1 };
        state.send(Event::RowsMoved {
            keys,
            to: to as usize,
        });
        true
    });
    widget.add_controller(target);
}
