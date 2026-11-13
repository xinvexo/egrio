//! The table component as a view-based `NSTableView`: the table asks for the
//! rows it shows, so a few thousand rows cost only the visible ones. A cell's
//! views are built once per shape and reused as the table scrolls. Updates
//! refill the views at their current positions, changing only the cells that
//! differ; selection follows row keys. Sorting and double clicks come back as
//! interface events; changes the interface makes itself (a new selection, a
//! new sort indicator) are applied quietly so they do not echo back.

use std::cell::{Cell as StdCell, RefCell};
use std::collections::HashMap;
use std::ptr::NonNull;
use std::sync::Arc;

use block2::StackBlock;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObjectProtocol, ProtocolObject};
use objc2::{
    define_class, msg_send, sel, AnyThread, DeclaredClass, MainThreadMarker, MainThreadOnly,
    Message,
};
use objc2_app_kit::{
    NSAnimationContext, NSBox, NSColor, NSControlTextEditingDelegate, NSDragOperation,
    NSDraggingInfo, NSDraggingSession, NSFont, NSImage, NSImageView, NSLayoutAttribute,
    NSLayoutConstraint, NSLayoutConstraintOrientation, NSLineBreakMode, NSPasteboardItem,
    NSPasteboardWriting, NSScrollView, NSStackView, NSStackViewGravity, NSTableColumn,
    NSTableColumnResizingOptions, NSTableRowView, NSTableView, NSTableViewColumnAutoresizingStyle,
    NSTableViewDataSource, NSTableViewDelegate, NSTableViewDraggingDestinationFeedbackStyle,
    NSTableViewDropOperation, NSTableViewSelectionHighlightStyle, NSTableViewStyle,
    NSTextAlignment, NSTextField, NSUserInterfaceItemIdentification,
    NSUserInterfaceLayoutOrientation, NSView,
};
use objc2_foundation::{
    NSArray, NSData, NSIndexSet, NSInteger, NSMutableIndexSet, NSNotification, NSObject, NSPoint,
    NSRect, NSSize, NSSortDescriptor, NSString,
};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{
    Badge, Cell, ColumnAlign, ColumnWidth, Image, KeyedChanges, Row, Selection, SortDirection,
    Table, TextStyle, Tone,
};
use egrio_ui::reconcile::NodeId;

use super::style;

struct Data {
    id: NodeId,
    post: fn(UiEvent),
    table: Table,
}

pub struct ControllerIvars {
    data: RefCell<Data>,
    /// Set while the interface itself changes the selection or the sort.
    quiet: StdCell<bool>,
    /// The keys of the rows being dragged.
    dragged: RefCell<Vec<String>>,
    /// A wrapping table's row heights, measured off screen.
    rows: RowHeights,
}

/// The heights of a wrapping table's rows: each row as tall as its longest
/// text wrapped in its column. The row height callback must not ask the table
/// for geometry, so the columns' text widths are taken when they change.
struct RowHeights {
    /// The width text has in each column.
    widths: RefCell<Vec<f64>>,
    /// Heights by row key, for those widths.
    cache: RefCell<HashMap<String, f64>>,
    measure: Retained<NSTextField>,
    body: Retained<NSFont>,
    mono: Retained<NSFont>,
}

impl RowHeights {
    fn new(mtm: MainThreadMarker) -> Self {
        Self {
            widths: RefCell::new(Vec::new()),
            cache: RefCell::new(HashMap::new()),
            measure: NSTextField::wrappingLabelWithString(&NSString::from_str(""), mtm),
            body: style::font(TextStyle::Body),
            mono: style::font(TextStyle::Mono),
        }
    }

    fn height(&self, row: &Row, least: f64) -> f64 {
        if let Some(height) = self.cache.borrow().get(&row.key) {
            return *height;
        }
        let widths = self.widths.borrow();
        let tallest = row
            .cells
            .iter()
            .zip(widths.iter())
            .filter_map(|(cell, width)| match cell {
                Cell::Text { text, mono, .. } => {
                    self.measure
                        .setFont(Some(if *mono { &self.mono } else { &self.body }));
                    self.measure.setStringValue(&NSString::from_str(text));
                    let bounds = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(*width, 1.0e5));
                    Some(self.measure.cell()?.cellSizeForBounds(bounds).height)
                }
                _ => None,
            })
            .fold(0.0, f64::max);
        let height = (tallest.ceil() + 2.0 * CELL_INSET).max(least);
        self.cache.borrow_mut().insert(row.key.clone(), height);
        height
    }

    /// Invalidates changed text by key and tells AppKit which positions need
    /// their heights queried again. Moving a row keeps its measurement.
    fn update(&self, props: &Table, old: &Table, changes: &KeyedChanges) -> Retained<NSIndexSet> {
        let mut cache = self.cache.borrow_mut();
        match changes {
            KeyedChanges::Edit {
                removed,
                inserted,
                changed,
            } => {
                for row in removed {
                    cache.remove(&old.rows[*row].key);
                }
                for row in changed {
                    cache.remove(&props.rows[*row].key);
                }
                if removed.is_empty() && inserted.is_empty() {
                    return index_set(changed).into_super();
                }
            }
            KeyedChanges::Reload => cache.clear(),
            KeyedChanges::None => return NSIndexSet::new(),
        }
        NSIndexSet::indexSetWithIndexesInRange(objc2_foundation::NSRange::new(0, props.rows.len()))
    }
}

/// The pasteboard type a dragged row carries its key in.
const ROW_TYPE: &str = "com.xinvexo.egrio.table-row";

/// The space above and below a cell's content in a wrapping row.
const CELL_INSET: f64 = 2.0;
/// The space before and after a cell's content.
const CELL_PADDING: f64 = 2.0;

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioTableController"]
    #[thread_kind = MainThreadOnly]
    #[ivars = ControllerIvars]
    pub struct TableController;

    unsafe impl NSObjectProtocol for TableController {}

    unsafe impl NSControlTextEditingDelegate for TableController {}

    unsafe impl NSTableViewDataSource for TableController {
        #[unsafe(method(numberOfRowsInTableView:))]
        fn number_of_rows(&self, _table: &NSTableView) -> NSInteger {
            self.ivars().data.borrow().table.rows.len() as NSInteger
        }

        #[unsafe(method(tableView:sortDescriptorsDidChange:))]
        fn sort_changed(&self, table: &NSTableView, _old: &NSArray<NSSortDescriptor>) {
            if self.ivars().quiet.get() {
                return;
            }
            let sort = table.sortDescriptors().firstObject().and_then(|descriptor| {
                let key = descriptor.key()?.to_string();
                let index: usize = key.strip_prefix('c')?.parse().ok()?;
                let direction = if descriptor.ascending() { SortDirection::Ascending } else { SortDirection::Descending };
                Some((index, direction))
            });
            let data = self.ivars().data.borrow();
            (data.post)(UiEvent::Node { id: data.id, event: Event::Sort(sort) });
        }

        // Rows the interface lets move are dragged within the table: each
        // carries its key, the drop goes between rows, and the interface
        // gets the keys and the row they were dropped before.
        #[unsafe(method_id(tableView:pasteboardWriterForRow:))]
        fn pasteboard_writer(
            &self,
            _table: &NSTableView,
            row: NSInteger,
        ) -> Option<Retained<ProtocolObject<dyn NSPasteboardWriting>>> {
            self.row_writer(row)
        }

        #[unsafe(method(tableView:draggingSession:willBeginAtPoint:forRowIndexes:))]
        fn drag_began(
            &self,
            _table: &NSTableView,
            _session: &NSDraggingSession,
            _point: NSPoint,
            rows: &NSIndexSet,
        ) {
            let data = self.ivars().data.borrow();
            *self.ivars().dragged.borrow_mut() = data
                .table
                .rows
                .iter()
                .enumerate()
                .filter(|(index, _)| rows.containsIndex(*index))
                .map(|(_, row)| row.key.clone())
                .collect();
        }

        #[unsafe(method(tableView:draggingSession:endedAtPoint:operation:))]
        fn drag_ended(
            &self,
            _table: &NSTableView,
            _session: &NSDraggingSession,
            _point: NSPoint,
            _operation: NSDragOperation,
        ) {
            self.ivars().dragged.borrow_mut().clear();
        }

        #[unsafe(method(tableView:validateDrop:proposedRow:proposedDropOperation:))]
        fn validate_drop(
            &self,
            table: &NSTableView,
            info: &ProtocolObject<dyn NSDraggingInfo>,
            row: NSInteger,
            _operation: NSTableViewDropOperation,
        ) -> NSDragOperation {
            let from_here = info.draggingSource().is_some_and(|source| {
                std::ptr::eq(Retained::as_ptr(&source).cast::<NSTableView>(), table)
            });
            if !from_here || self.ivars().dragged.borrow().is_empty() {
                return NSDragOperation::None;
            }
            // Between rows, never onto one.
            table.setDropRow_dropOperation(row, NSTableViewDropOperation::Above);
            NSDragOperation::Move
        }

        #[unsafe(method(tableView:acceptDrop:row:dropOperation:))]
        fn accept_drop(
            &self,
            _table: &NSTableView,
            _info: &ProtocolObject<dyn NSDraggingInfo>,
            row: NSInteger,
            _operation: NSTableViewDropOperation,
        ) -> bool {
            self.drop_rows(row)
        }
    }

    unsafe impl NSTableViewDelegate for TableController {
        #[unsafe(method_id(tableView:viewForTableColumn:row:))]
        fn view_for(&self, table: &NSTableView, column: Option<&NSTableColumn>, row: NSInteger) -> Option<Retained<NSView>> {
            self.cell_for(table, column, row)
        }

        #[unsafe(method(tableView:heightOfRow:))]
        fn height_of_row(&self, _table: &NSTableView, row: NSInteger) -> f64 {
            let data = self.ivars().data.borrow();
            let least = data.table.row_height;
            match usize::try_from(row).ok().and_then(|row| data.table.rows.get(row)) {
                Some(row) if data.table.wrap => self.ivars().rows.height(row, least),
                _ => least,
            }
        }

        #[unsafe(method(tableViewColumnDidResize:))]
        fn column_resized(&self, notification: &NSNotification) {
            let Some(table) = notification.object() else { return };
            let table: &NSTableView = unsafe { &*(Retained::as_ptr(&table) as *const NSTableView) };
            if self.ivars().data.borrow().table.wrap {
                self.remeasure(table);
            }
        }

        #[unsafe(method(tableViewSelectionDidChange:))]
        fn selection_changed(&self, notification: &NSNotification) {
            if self.ivars().quiet.get() {
                return;
            }
            let Some(table) = notification.object() else { return };
            let table: &NSTableView = unsafe { &*(Retained::as_ptr(&table) as *const NSTableView) };
            let data = self.ivars().data.borrow();
            let selected = table.selectedRowIndexes();
            let keys: Vec<String> = data
                .table
                .rows
                .iter()
                .enumerate()
                .filter(|(index, _)| selected.containsIndex(*index))
                .map(|(_, row)| row.key.clone())
                .collect();
            (data.post)(UiEvent::Node { id: data.id, event: Event::RowsSelected(keys) });
        }
    }

    impl TableController {
        #[unsafe(method(activateRow:))]
        fn activate_row(&self, sender: &NSTableView) {
            let row = sender.clickedRow();
            let data = self.ivars().data.borrow();
            if let Some(row) = usize::try_from(row).ok().and_then(|row| data.table.rows.get(row)) {
                (data.post)(UiEvent::Node { id: data.id, event: Event::RowActivated(row.key.clone()) });
            }
        }
    }
);

impl TableController {
    /// A row's key on the pasteboard, while the interface lets rows move.
    fn row_writer(
        &self,
        row: NSInteger,
    ) -> Option<Retained<ProtocolObject<dyn NSPasteboardWriting>>> {
        let data = self.ivars().data.borrow();
        data.table.on_move.as_ref()?;
        let row = data.table.rows.get(usize::try_from(row).ok()?)?;
        let item = NSPasteboardItem::new();
        item.setString_forType(&NSString::from_str(&row.key), &NSString::from_str(ROW_TYPE));
        Some(ProtocolObject::from_retained(item))
    }

    /// The dragged rows dropped before `row`: the interface decides.
    fn drop_rows(&self, row: NSInteger) -> bool {
        let keys = std::mem::take(&mut *self.ivars().dragged.borrow_mut());
        let Ok(to) = usize::try_from(row) else {
            return false;
        };
        if keys.is_empty() {
            return false;
        }
        let data = self.ivars().data.borrow();
        (data.post)(UiEvent::Node {
            id: data.id,
            event: Event::RowsMoved { keys, to },
        });
        true
    }

    /// Takes the columns' text widths and has the table ask for every row's
    /// height again.
    fn remeasure(&self, table: &NSTableView) {
        // A cell view is as wide as its column; the text field's frame reaches
        // past the cell's padding by its alignment insets.
        let insets = self.ivars().rows.measure.alignmentRectInsets();
        let widths: Vec<f64> = table
            .tableColumns()
            .iter()
            .map(|column| {
                (column.width() - 2.0 * CELL_PADDING + insets.left + insets.right).max(1.0)
            })
            .collect();
        let rows = self.ivars().data.borrow().table.rows.len();
        *self.ivars().rows.widths.borrow_mut() = widths;
        self.ivars().rows.cache.borrow_mut().clear();
        table.noteHeightOfRowsWithIndexesChanged(&NSIndexSet::indexSetWithIndexesInRange(
            objc2_foundation::NSRange {
                location: 0,
                length: rows,
            },
        ));
    }

    fn cell_for(
        &self,
        table: &NSTableView,
        column: Option<&NSTableColumn>,
        row: NSInteger,
    ) -> Option<Retained<NSView>> {
        let mtm = MainThreadMarker::from(self);
        let data = self.ivars().data.borrow();
        let row = data.table.rows.get(usize::try_from(row).ok()?)?;
        let index = column
            .map(|column| column.identifier().to_string())
            .and_then(|identifier| {
                identifier
                    .strip_prefix('c')
                    .and_then(|index| index.parse::<usize>().ok())
            })
            .unwrap_or(0);
        let cell = row.cells.get(index)?;
        let align = data
            .table
            .columns
            .get(index)
            .map(|column| column.align)
            .unwrap_or(ColumnAlign::Leading);
        let wrap = data.table.wrap;
        // A view of the same shape that scrolled out of sight, or a new one.
        let identifier = identifier(cell, align, wrap);
        let view =
            unsafe { table.makeViewWithIdentifier_owner(&NSString::from_str(&identifier), None) }
                .and_then(|view| view.downcast::<CellView>().ok())
                .unwrap_or_else(|| CellView::new(mtm, cell, align, wrap, identifier));
        fill(&view.ivars().parts, cell);
        Some(Retained::into_super(view))
    }
}

pub struct TableHost {
    container: Retained<NSView>,
    table: Retained<NSTableView>,
    controller: Retained<TableController>,
    empty: Retained<NSTextField>,
    scroll: Retained<NSScrollView>,
}

impl TableHost {
    pub fn new(mtm: MainThreadMarker, id: NodeId, props: &Table, post: fn(UiEvent)) -> Self {
        let controller = TableController::alloc(mtm).set_ivars(ControllerIvars {
            data: RefCell::new(Data {
                id,
                post,
                table: props.clone(),
            }),
            quiet: StdCell::new(false),
            dragged: RefCell::new(Vec::new()),
            rows: RowHeights::new(mtm),
        });
        let controller: Retained<TableController> = unsafe { msg_send![super(controller), init] };
        let table = NSTableView::new(mtm);
        table.setStyle(NSTableViewStyle::Plain);
        table.setUsesAlternatingRowBackgroundColors(false);
        table.setIntercellSpacing(objc2_foundation::NSSize {
            width: 8.0,
            height: 0.0,
        });
        table.setColumnAutoresizingStyle(
            NSTableViewColumnAutoresizingStyle::UniformColumnAutoresizingStyle,
        );
        unsafe {
            table.setDataSource(Some(objc2::runtime::ProtocolObject::from_ref(&*controller)));
            table.setDelegate(Some(objc2::runtime::ProtocolObject::from_ref(&*controller)));
            let target: &AnyObject = controller.as_ref();
            table.setTarget(Some(target));
            table.setDoubleAction(Some(sel!(activateRow:)));
        }
        let scroll = NSScrollView::new(mtm);
        scroll.setDocumentView(Some(&table));
        scroll.setHasVerticalScroller(true);
        scroll.setAutohidesScrollers(true);
        scroll.setDrawsBackground(false);
        let container = NSView::new(mtm);
        super::widgets::pin(&scroll, &container, 0.0);
        let empty = NSTextField::labelWithString(&NSString::from_str(""), mtm);
        empty.setTextColor(Some(&NSColor::secondaryLabelColor()));
        empty.setFont(Some(&style::font(TextStyle::Caption)));
        empty.setTranslatesAutoresizingMaskIntoConstraints(false);
        container.addSubview(&empty);
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
            empty
                .centerXAnchor()
                .constraintEqualToAnchor(&container.centerXAnchor()),
            empty
                .centerYAnchor()
                .constraintEqualToAnchor(&container.centerYAnchor()),
        ]));
        let host = Self {
            container,
            table,
            controller,
            empty,
            scroll,
        };
        host.configure(props, None);
        host.table.reloadData();
        host.apply_selection(props);
        if props.follow_end {
            host.scroll_to_end();
        }
        host
    }

    pub fn view(&self) -> Retained<NSView> {
        self.container.clone()
    }

    pub fn update(&self, props: &Table) {
        let old = self.controller.ivars().data.borrow().table.clone();
        self.controller.ivars().data.borrow_mut().table = props.clone();
        self.configure(props, Some(&old));
        let follow = props.follow_end && self.at_end();
        let layout_changed = old.columns != props.columns || old.wrap != props.wrap;
        let changes = if layout_changed {
            KeyedChanges::Reload
        } else {
            props.row_changes(&old)
        };
        if changes != KeyedChanges::None {
            self.quietly(|| {
                let heights = props
                    .wrap
                    .then(|| self.controller.ivars().rows.update(props, &old, &changes));
                // Native views belong to visible positions. Refill those
                // positions instead of moving every retained row view when
                // short-lived connections push new rows into a full history.
                // NSTableView.h: noteNumberOfRowsChanged changes the count at
                // the end; enumerateAvailableRowViews includes retained views.
                NSAnimationContext::beginGrouping();
                NSAnimationContext::currentContext().setDuration(0.0);
                if props.rows.len() != old.rows.len() {
                    self.table.noteNumberOfRowsChanged();
                }
                let available = RefCell::new(Vec::new());
                self.table
                    .enumerateAvailableRowViewsUsingBlock(&StackBlock::new(
                        |_: NonNull<NSTableRowView>, row: NSInteger| {
                            // Views of rows just removed can still be in flight.
                            if (0..props.rows.len() as NSInteger).contains(&row) {
                                available.borrow_mut().push(row as usize);
                            }
                        },
                    ));
                let reload: Vec<usize> = available
                    .into_inner()
                    .into_iter()
                    .filter(|row| layout_changed || old.rows.get(*row) != props.rows.get(*row))
                    .filter(|row| !self.refill_row(props, &old, *row))
                    .collect();
                if !reload.is_empty() {
                    let columns =
                        NSIndexSet::indexSetWithIndexesInRange(objc2_foundation::NSRange {
                            location: 0,
                            length: props.columns.len(),
                        });
                    self.table
                        .reloadDataForRowIndexes_columnIndexes(&index_set(&reload), &columns);
                }
                if let Some(heights) = heights {
                    self.table.noteHeightOfRowsWithIndexesChanged(&heights);
                }
                NSAnimationContext::endGrouping();
            });
        }
        self.apply_selection(props);
        if follow {
            self.scroll_to_end();
        }
    }

    /// Whether the table shows its last rows, give or take two rows.
    fn at_end(&self) -> bool {
        let visible = self.scroll.contentView().bounds();
        let height = self.table.frame().size.height;
        visible.origin.y + visible.size.height >= height - 2.0 * self.table.rowHeight()
    }

    fn scroll_to_end(&self) {
        let rows = self.table.numberOfRows();
        if rows > 0 {
            self.table.scrollRowToVisible(rows - 1);
        }
    }

    /// Gives the views the table holds for `row` the row's new content;
    /// false when a cell's shape changed, so its views cannot show it.
    fn refill_row(&self, props: &Table, old: &Table, row: usize) -> bool {
        for (column, cell) in props.rows[row].cells.iter().enumerate() {
            if old.wrap == props.wrap
                && old.columns.get(column) == props.columns.get(column)
                && old.rows.get(row).and_then(|row| row.cells.get(column)) == Some(cell)
            {
                continue;
            }
            // Only rows the table shows (or keeps ready) have views.
            let Some(view) = self.table.viewAtColumn_row_makeIfNecessary(
                column as NSInteger,
                row as NSInteger,
                false,
            ) else {
                continue;
            };
            let align = props.columns[column].align;
            let view = view.downcast::<CellView>().expect("table cell view");
            if view.ivars().identifier != identifier(cell, align, props.wrap) {
                return false;
            }
            fill(&view.ivars().parts, cell);
        }
        true
    }

    fn quietly(&self, change: impl FnOnce()) {
        let quiet = &self.controller.ivars().quiet;
        let previous = quiet.replace(true);
        change();
        quiet.set(previous);
    }

    /// Columns, header, row height, selection mode, sort indicator and the
    /// empty text, where they differ from `old`.
    fn configure(&self, props: &Table, old: Option<&Table>) {
        let mtm = MainThreadMarker::from(&*self.table);
        let columns_changed = old.is_none_or(|old| old.columns != props.columns);
        if columns_changed {
            for column in self.table.tableColumns().iter() {
                self.table.removeTableColumn(&column);
            }
            for (index, props_column) in props.columns.iter().enumerate() {
                let column = NSTableColumn::initWithIdentifier(
                    NSTableColumn::alloc(mtm),
                    &NSString::from_str(&format!("c{index}")),
                );
                column.setTitle(&NSString::from_str(&props_column.title));
                match props_column.width {
                    ColumnWidth::Fixed(width) => {
                        column.setWidth(width);
                        column.setMinWidth(width);
                        column.setMaxWidth(width);
                        column.setResizingMask(NSTableColumnResizingOptions::empty());
                    }
                    ColumnWidth::Flexible { min } => {
                        column.setMinWidth(min);
                        column.setWidth(min.max(200.0));
                        column.setMaxWidth(10_000.0);
                        column.setResizingMask(NSTableColumnResizingOptions::AutoresizingMask);
                    }
                }
                if props_column.align == ColumnAlign::Trailing {
                    column.headerCell().setAlignment(NSTextAlignment::Right);
                }
                if props_column.sortable {
                    let ascending = props_column.align != ColumnAlign::Trailing;
                    let descriptor = NSSortDescriptor::sortDescriptorWithKey_ascending(
                        Some(&NSString::from_str(&format!("c{index}"))),
                        ascending,
                    );
                    column.setSortDescriptorPrototype(Some(&descriptor));
                }
                self.table.addTableColumn(&column);
            }
            self.table.sizeLastColumnToFit();
        }
        if old.is_none_or(|old| old.header != props.header) {
            if props.header {
                if self.table.headerView().is_none() {
                    self.table
                        .setHeaderView(Some(&objc2_app_kit::NSTableHeaderView::new(mtm)));
                }
            } else {
                self.table.setHeaderView(None);
            }
        }
        if old.is_none_or(|old| old.row_height != props.row_height) {
            self.table.setRowHeight(props.row_height);
        }
        let movable = props.on_move.is_some();
        if old.is_none_or(|old| old.on_move.is_some() != movable) {
            if movable {
                self.table
                    .registerForDraggedTypes(&NSArray::from_retained_slice(&[NSString::from_str(
                        ROW_TYPE,
                    )]));
                self.table.setDraggingDestinationFeedbackStyle(
                    NSTableViewDraggingDestinationFeedbackStyle::Gap,
                );
                self.table
                    .setDraggingSourceOperationMask_forLocal(NSDragOperation::Move, true);
            } else {
                self.table.unregisterDraggedTypes();
            }
        }
        if props.wrap && (columns_changed || old.is_none_or(|old| !old.wrap)) {
            self.controller.remeasure(&self.table);
        }
        if old.is_none_or(|old| old.selection != props.selection) {
            self.table
                .setAllowsMultipleSelection(props.selection == Selection::Multiple);
            self.table.setAllowsEmptySelection(true);
            self.table
                .setSelectionHighlightStyle(if props.selection == Selection::None {
                    NSTableViewSelectionHighlightStyle::None
                } else {
                    NSTableViewSelectionHighlightStyle::Regular
                });
        }
        if columns_changed || old.is_none_or(|old| old.sort != props.sort) {
            let descriptors: Vec<Retained<NSSortDescriptor>> = props
                .sort
                .map(|(index, direction)| {
                    NSSortDescriptor::sortDescriptorWithKey_ascending(
                        Some(&NSString::from_str(&format!("c{index}"))),
                        direction == SortDirection::Ascending,
                    )
                })
                .into_iter()
                .collect();
            self.quietly(|| {
                self.table
                    .setSortDescriptors(&NSArray::from_retained_slice(&descriptors))
            });
        }
        let empty = props.rows.is_empty();
        self.empty.setStringValue(&NSString::from_str(if empty {
            props.empty.as_deref().unwrap_or("")
        } else {
            ""
        }));
        self.empty.setHidden(!empty);
    }

    /// Selects the rows the interface names, if the table's own selection differs.
    fn apply_selection(&self, props: &Table) {
        let wanted: Vec<usize> = props
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| props.selected.contains(&row.key))
            .map(|(index, _)| index)
            .collect();
        let current = self.table.selectedRowIndexes();
        let same = current.count() == wanted.len()
            && wanted.iter().all(|index| current.containsIndex(*index));
        if same {
            return;
        }
        self.quietly(|| {
            self.table
                .selectRowIndexes_byExtendingSelection(&index_set(&wanted), false)
        });
    }
}

/// Whether the table's rows can be dragged to another place.
#[cfg(feature = "test-control")]
pub fn rows_move(table: &NSTableView) -> bool {
    controller(table)
        .is_some_and(|controller| controller.ivars().data.borrow().table.on_move.is_some())
}

/// Drops the `from`th row before the `to`th, as a finished drag does.
#[cfg(feature = "test-control")]
pub fn drop_rows(table: &NSTableView, from: usize, to: usize) -> Result<(), String> {
    let controller = controller(table).ok_or("not an interface table")?;
    let key = controller
        .ivars()
        .data
        .borrow()
        .table
        .rows
        .get(from)
        .map(|row| row.key.clone())
        .ok_or("no such row")?;
    *controller.ivars().dragged.borrow_mut() = vec![key];
    if controller.drop_rows(to as NSInteger) {
        Ok(())
    } else {
        Err("the drop was refused".into())
    }
}

#[cfg(feature = "test-control")]
fn controller(table: &NSTableView) -> Option<Retained<TableController>> {
    let source = unsafe { table.dataSource() }?;
    let object: Retained<AnyObject> = unsafe { Retained::cast_unchecked(source) };
    object.downcast::<TableController>().ok()
}

fn index_set(indexes: &[usize]) -> Retained<NSMutableIndexSet> {
    let set = NSMutableIndexSet::new();
    for index in indexes {
        set.addIndex(*index);
    }
    set
}

thread_local! {
    /// Decoded app icons, by the identity of their PNG data.
    static IMAGES: RefCell<HashMap<usize, Retained<NSImage>>> = RefCell::new(HashMap::new());
}

fn image(data: &Image) -> Option<Retained<NSImage>> {
    let key = Arc::as_ptr(&data.0) as *const u8 as usize;
    IMAGES.with(|images| {
        if let Some(image) = images.borrow().get(&key) {
            return Some(image.clone());
        }
        let bytes = NSData::with_bytes(&data.0);
        let image = NSImage::initWithData(NSImage::alloc(), &bytes)?;
        images.borrow_mut().insert(key, image.clone());
        Some(image)
    })
}

fn text(mtm: MainThreadMarker, style_: TextStyle) -> Retained<NSTextField> {
    let field = NSTextField::labelWithString(&NSString::from_str(""), mtm);
    field.setFont(Some(&style::font(style_)));
    field.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
    field.setAllowsExpansionToolTips(true);
    field.setContentCompressionResistancePriority_forOrientation(
        super::widgets::TEXT_COMPRESSION,
        NSLayoutConstraintOrientation::Horizontal,
    );
    field
}

fn line(mtm: MainThreadMarker, spacing: f64) -> Retained<NSStackView> {
    let stack = NSStackView::new(mtm);
    stack.setOrientation(NSUserInterfaceLayoutOrientation::Horizontal);
    stack.setSpacing(spacing);
    stack.setAlignment(NSLayoutAttribute::CenterY);
    stack
}

fn icon_view(mtm: MainThreadMarker, size: f64) -> Retained<NSImageView> {
    let view = NSImageView::new(mtm);
    view.setContentTintColor(Some(&NSColor::secondaryLabelColor()));
    view.setTranslatesAutoresizingMaskIntoConstraints(false);
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        view.widthAnchor().constraintEqualToConstant(size),
        view.heightAnchor().constraintEqualToConstant(size),
    ]));
    view
}

thread_local! {
    /// Symbols and status dots, made once each.
    static SYMBOLS: RefCell<HashMap<&'static str, Option<Retained<NSImage>>>> = RefCell::new(HashMap::new());
    static DOTS: RefCell<HashMap<Tone, Option<Retained<NSImage>>>> = RefCell::new(HashMap::new());
}

fn symbol(name: &'static str) -> Option<Retained<NSImage>> {
    SYMBOLS.with(|symbols| {
        symbols
            .borrow_mut()
            .entry(name)
            .or_insert_with(|| style::named_symbol(name))
            .clone()
    })
}

fn dot(tone: Tone) -> Option<Retained<NSImage>> {
    DOTS.with(|dots| {
        dots.borrow_mut()
            .entry(tone)
            .or_insert_with(|| style::colored_symbol("circle.fill", &style::color(tone), 6.0))
            .clone()
    })
}

/// The views a cell shows its content in.
enum Parts {
    Text(Retained<NSTextField>),
    Badge {
        surface: Retained<NSBox>,
        label: Retained<NSTextField>,
    },
    Status {
        dot: Retained<NSImageView>,
        label: Retained<NSTextField>,
    },
    Process {
        icon: Retained<NSImageView>,
        name: Retained<NSTextField>,
    },
    TwoLine {
        icon: Retained<NSImageView>,
        title: Retained<NSTextField>,
        detail: Retained<NSTextField>,
        trailing: Retained<NSTextField>,
    },
    Inline(Vec<Parts>),
}

/// What a cell's views look like before any content: cells of one shape
/// share their views as the table scrolls.
fn shape(cell: &Cell) -> String {
    match cell {
        Cell::Text { mono: false, .. } => "text".into(),
        Cell::Text { mono: true, .. } => "mono".into(),
        Cell::Number(_) => "number".into(),
        Cell::Badge { .. } => "badge".into(),
        Cell::Status { .. } => "status".into(),
        Cell::Process { .. } => "process".into(),
        Cell::TwoLine { .. } => "two-line".into(),
        Cell::Inline(cells) => {
            let parts: Vec<String> = cells.iter().map(shape).collect();
            format!("inline({})", parts.join(","))
        }
    }
}

fn identifier(cell: &Cell, align: ColumnAlign, wrap: bool) -> String {
    let side = match align {
        ColumnAlign::Leading => "leading",
        ColumnAlign::Trailing => "trailing",
    };
    let lines = if wrap { "wrapped" } else { "line" };
    format!("egrio.cell.{}.{side}.{lines}", shape(cell))
}

/// Selectable text over as many lines as it needs.
fn wrapping_text(mtm: MainThreadMarker, style_: TextStyle) -> Retained<NSTextField> {
    let field = NSTextField::wrappingLabelWithString(&NSString::from_str(""), mtm);
    field.setFont(Some(&style::font(style_)));
    field.setLineBreakMode(NSLineBreakMode::ByWordWrapping);
    field.setContentCompressionResistancePriority_forOrientation(
        super::widgets::TEXT_COMPRESSION,
        NSLayoutConstraintOrientation::Horizontal,
    );
    field
}

fn build(
    mtm: MainThreadMarker,
    cell: &Cell,
    align: ColumnAlign,
    wrap: bool,
) -> (Retained<NSView>, Parts) {
    match cell {
        Cell::Text { mono, .. } => {
            let style_ = if *mono {
                TextStyle::Mono
            } else {
                TextStyle::Body
            };
            let field = if wrap {
                wrapping_text(mtm, style_)
            } else {
                text(mtm, style_)
            };
            if align == ColumnAlign::Trailing {
                field.setAlignment(NSTextAlignment::Right);
            }
            (as_view(&field), Parts::Text(field))
        }
        Cell::Number(_) => {
            let field = text(mtm, TextStyle::Body);
            field.setFont(Some(&style::numeric_font(12.0)));
            field.setTextColor(Some(&style::color(Tone::Muted)));
            field.setAlignment(NSTextAlignment::Right);
            (as_view(&field), Parts::Text(field))
        }
        Cell::Badge { .. } => {
            let (surface, label) = super::widgets::badge(mtm, "", Tone::Default);
            (as_view(&surface), Parts::Badge { surface, label })
        }
        Cell::Status { .. } => {
            let row = line(mtm, 5.0);
            let dot = icon_view(mtm, 7.0);
            let label = text(mtm, TextStyle::Body);
            row.addArrangedSubview(&dot);
            row.addArrangedSubview(&label);
            (as_view(&row), Parts::Status { dot, label })
        }
        Cell::Process { .. } => {
            let row = line(mtm, 6.0);
            let icon = icon_view(mtm, 16.0);
            let name = text(mtm, TextStyle::Body);
            row.addArrangedSubview(&icon);
            row.addArrangedSubview(&name);
            (as_view(&row), Parts::Process { icon, name })
        }
        Cell::TwoLine { .. } => {
            let row = line(mtm, 8.0);
            // The lines take the room left, so the figure ends the row.
            row.setDistribution(objc2_app_kit::NSStackViewDistribution::Fill);
            let icon = icon_view(mtm, 16.0);
            row.addArrangedSubview(&icon);
            let lines = NSStackView::new(mtm);
            lines.setOrientation(NSUserInterfaceLayoutOrientation::Vertical);
            lines.setAlignment(NSLayoutAttribute::Leading);
            lines.setSpacing(1.0);
            let title = text(mtm, TextStyle::Body);
            let detail = text(mtm, TextStyle::Caption);
            detail.setTextColor(Some(&style::color(Tone::Muted)));
            lines.addArrangedSubview(&title);
            lines.addArrangedSubview(&detail);
            lines.setContentHuggingPriority_forOrientation(
                1.0,
                NSLayoutConstraintOrientation::Horizontal,
            );
            row.addArrangedSubview(&lines);
            let trailing = text(mtm, TextStyle::Caption);
            trailing.setFont(Some(&style::numeric_font(11.0)));
            trailing.setTextColor(Some(&style::color(Tone::Muted)));
            trailing.setContentCompressionResistancePriority_forOrientation(
                750.0,
                NSLayoutConstraintOrientation::Horizontal,
            );
            row.addArrangedSubview(&trailing);
            (
                as_view(&row),
                Parts::TwoLine {
                    icon,
                    title,
                    detail,
                    trailing,
                },
            )
        }
        Cell::Inline(cells) => {
            // The first cell in the leading gravity area, its tags in the
            // trailing one, at the column's end.
            let row = line(mtm, 6.0);
            let parts = cells
                .iter()
                .enumerate()
                .map(|(index, cell)| {
                    let (view, parts) = build(mtm, cell, ColumnAlign::Leading, wrap);
                    let gravity = if index == 0 {
                        NSStackViewGravity::Leading
                    } else {
                        NSStackViewGravity::Trailing
                    };
                    row.addView_inGravity(&view, gravity);
                    parts
                })
                .collect();
            (as_view(&row), Parts::Inline(parts))
        }
    }
}

/// Gives a cell's views this row's content; `parts` came from a cell of the
/// same shape.
fn fill(parts: &Parts, cell: &Cell) {
    let set = |field: &NSTextField, value: &str| field.setStringValue(&NSString::from_str(value));
    match (parts, cell) {
        (Parts::Text(field), Cell::Text { text, tone, .. }) => {
            set(field, text);
            field.setTextColor(Some(&style::color(*tone)));
        }
        (Parts::Text(field), Cell::Number(value)) => set(field, value),
        (Parts::Badge { surface, label }, Cell::Badge { text, tone }) => {
            super::widgets::style_badge(
                label,
                surface,
                &Badge {
                    text: text.clone(),
                    tone: *tone,
                },
            );
        }
        (Parts::Status { dot: mark, label }, Cell::Status { text, tone }) => {
            mark.setImage(dot(*tone).as_deref());
            set(label, text);
            label.setTextColor(Some(&style::color(*tone)));
        }
        (
            Parts::Process { icon, name },
            Cell::Process {
                name: value,
                icon: picture,
            },
        ) => {
            icon.setImage(
                picture
                    .as_ref()
                    .and_then(image)
                    .or_else(|| symbol("app"))
                    .as_deref(),
            );
            set(name, value);
        }
        (
            Parts::TwoLine {
                icon,
                title,
                detail,
                trailing,
            },
            Cell::TwoLine {
                title: heading,
                detail: line,
                icon: picture,
                fallback,
                trailing: figure,
                trailing_tone,
            },
        ) => {
            let picture = picture
                .as_ref()
                .and_then(image)
                .or_else(|| symbol(style::symbol_name(*fallback)));
            icon.setImage(picture.as_deref());
            set(title, heading);
            set(detail, line);
            set(trailing, figure);
            trailing.setTextColor(Some(&style::color(*trailing_tone)));
        }
        (Parts::Inline(parts), Cell::Inline(cells)) => {
            for (parts, cell) in parts.iter().zip(cells) {
                fill(parts, cell);
            }
        }
        _ => {}
    }
}

fn as_view<T: AsRef<NSView>>(view: &Retained<T>) -> Retained<NSView> {
    let view: &NSView = (**view).as_ref();
    view.retain()
}

pub struct CellIvars {
    identifier: String,
    parts: Parts,
}

define_class!(
    /// A cell's view: its content vertically centered in the column. The
    /// table keeps views that scroll out of sight and hands them back for
    /// other cells of the same shape.
    #[unsafe(super(NSView))]
    #[name = "EgrioTableCell"]
    #[thread_kind = MainThreadOnly]
    #[ivars = CellIvars]
    struct CellView;

    unsafe impl NSObjectProtocol for CellView {}
);

impl CellView {
    fn new(
        mtm: MainThreadMarker,
        cell: &Cell,
        align: ColumnAlign,
        wrap: bool,
        identifier: String,
    ) -> Retained<Self> {
        let (inner, parts) = build(mtm, cell, align, wrap);
        let name = NSString::from_str(&identifier);
        let this = Self::alloc(mtm).set_ivars(CellIvars { identifier, parts });
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        this.setIdentifier(Some(&name));
        inner.setTranslatesAutoresizingMaskIntoConstraints(false);
        this.addSubview(&inner);
        // A wrapping table's rows are as tall as their tallest cell, and every
        // cell starts at the top; otherwise a row has the table's height and
        // its cells sit in the middle.
        let vertical = if wrap {
            let bottom = if matches!(cell, Cell::Text { .. }) {
                // Wrapped text takes the row's height, which was measured for it.
                inner
                    .bottomAnchor()
                    .constraintEqualToAnchor_constant(&this.bottomAnchor(), -CELL_INSET)
            } else {
                inner
                    .bottomAnchor()
                    .constraintLessThanOrEqualToAnchor_constant(&this.bottomAnchor(), -CELL_INSET)
            };
            vec![
                inner
                    .topAnchor()
                    .constraintEqualToAnchor_constant(&this.topAnchor(), CELL_INSET),
                bottom,
            ]
        } else {
            vec![inner
                .centerYAnchor()
                .constraintEqualToAnchor(&this.centerYAnchor())]
        };
        let mut constraints = vertical;
        constraints.extend([
            inner
                .leadingAnchor()
                .constraintGreaterThanOrEqualToAnchor_constant(&this.leadingAnchor(), CELL_PADDING),
            inner
                .trailingAnchor()
                .constraintLessThanOrEqualToAnchor_constant(&this.trailingAnchor(), -CELL_PADDING),
        ]);
        // Text runs to both edges, so it truncates, and so do a cell's tags,
        // which end the column; a badge keeps its size at its column's side.
        let fills = !matches!(cell, Cell::Badge { .. });
        if fills || align == ColumnAlign::Leading {
            constraints.push(
                inner
                    .leadingAnchor()
                    .constraintEqualToAnchor_constant(&this.leadingAnchor(), CELL_PADDING),
            );
        }
        if fills || align == ColumnAlign::Trailing {
            constraints.push(
                inner
                    .trailingAnchor()
                    .constraintEqualToAnchor_constant(&this.trailingAnchor(), -CELL_PADDING),
            );
        }
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&constraints));
        this
    }
}
