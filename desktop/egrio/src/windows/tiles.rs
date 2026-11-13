//! The tile grid as a `GridView` whose wrapping panel lays tiles in rows: as
//! many to a row as fit at their least width, stretched to share the row.
//! The grid view builds containers only for the tiles it shows and fills a
//! container when it comes into view, like the table; a changed tile on
//! screen takes its new content in place. A tile is drawn like a card and
//! acts as a button when it is pressable. The selected tile has the accent
//! edge, and a check mark after its title where the grid checks its
//! selection. A testable tile's value is a subtle button of its own at the
//! end of its second line, the test symbol before its first result, which
//! takes its own clicks and reports a test instead of a press.

use std::cell::RefCell;
use std::rc::Rc;

use windows_core::{EventRevoker, Interface, Result};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{Icon, KeyedChanges, TextStyle, Tile, TileValue, Tiles, Tone};
use egrio_ui::reconcile::NodeId;

use super::bindings::{
    AutomationProperties, Button, ColumnDefinition, FontIcon, FrameworkElement, Grid, GridView,
    HorizontalAlignment, IButtonBase, IContentControl, IControl, IItemContainerMapping,
    IItemsControl, IItemsWrapGrid, IListViewBase, IPanel, ListViewSelectionMode, ProgressRing,
    RowDefinition, TextBlock, Thickness, ToolTipService, UIElement, VerticalAlignment, Visibility,
};
use super::widgets::{check, label, Post};
use super::xaml::{self, Element};

/// Space between tiles, across and down.
const SPACING: f64 = 10.0;
/// Space inside a tile's edges.
const INSET: f64 = 14.0;
/// The edge of a tile, and of the selected one.
const EDGE: f64 = 1.0;
const SELECTED_EDGE: f64 = 2.0;
/// Space around the test button's content, which its highlight covers.
const TEST_PADDING: f64 = 4.0;
/// The width a scroll viewer keeps for its vertical scroll bar.
const SCROLL_BAR: f64 = 16.0;

struct State {
    id: NodeId,
    post: Post,
    tiles: RefCell<Tiles>,
}

pub struct TilesHost {
    root: Grid,
    grid: GridView,
    empty: TextBlock,
    state: Rc<State>,
    _events: Vec<EventRevoker>,
}

#[cfg(feature = "test-control")]
/// What the test control channel drives a tile grid by: its tiles as
/// shown, and a press on one of them.
impl TilesHost {
    /// Each tile as it reads: its title, what it holds and its value, with
    /// a check on the one in use.
    pub(super) fn shown(&self) -> Vec<String> {
        self.state
            .tiles
            .borrow()
            .tiles
            .iter()
            .map(|tile| {
                let mut text = tile.title.clone();
                if let Some(detail) = &tile.detail {
                    text.push_str(&format!(" · {detail}"));
                }
                if let egrio_ui::node::TileValue::Text { text: value, .. } = &tile.value {
                    text.push_str(&format!(" · {value}"));
                }
                if tile.selected {
                    text.push_str(" ✓");
                }
                if !tile.pressable {
                    text.push_str(" (not pressable)");
                }
                text
            })
            .collect()
    }

    pub(super) fn tiles(&self) -> Vec<String> {
        self.state
            .tiles
            .borrow()
            .tiles
            .iter()
            .map(|tile| tile.key.clone())
            .collect()
    }

    pub(super) fn press(&self, key: String) {
        (self.state.post)(UiEvent::Node {
            id: self.state.id,
            event: Event::TilePressed(key),
        });
    }
}

impl TilesHost {
    pub fn new(id: NodeId, props: &Tiles, post: Post) -> Result<Self> {
        let state = Rc::new(State {
            id,
            post,
            tiles: RefCell::new(props.clone()),
        });
        let root = Grid::new()?;
        let grid = GridView::new()?;
        let items = grid.cast::<IItemsControl>()?;
        items.SetItemTemplate(&xaml::empty_template("Grid")?)?;
        items.SetItemsPanel(&xaml::load::<super::bindings::ItemsPanelTemplate>(
            "ItemsPanelTemplate",
            "",
            "<ItemsWrapGrid Orientation='Horizontal'/>",
        )?)?;
        items.SetItemContainerStyle(&xaml::style(
            "GridViewItem",
            Some("DefaultGridViewItemStyle"),
            &[
                ("Margin", format!("0,0,{SPACING},{SPACING}")),
                ("HorizontalContentAlignment", "Stretch".into()),
                ("VerticalContentAlignment", "Stretch".into()),
            ],
        )?)?;
        // Each tile's slot ends in the spacing after it, which the last tile
        // of a row puts beyond the page's edge, with the width the scroll
        // viewer keeps for its scroll bar.
        grid.fe().SetMargin(Thickness {
            left: 0.0,
            top: 0.0,
            right: -(SPACING + SCROLL_BAR),
            bottom: 0.0,
        })?;
        let list = grid.cast::<IListViewBase>()?;
        list.SetSelectionMode(ListViewSelectionMode::None)?;
        list.SetIsItemClickEnabled(true)?;
        let empty = label("", TextStyle::Caption, Tone::Muted)?;
        empty
            .fe()
            .SetHorizontalAlignment(HorizontalAlignment::Center)?;
        empty.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        empty.ui().SetIsHitTestVisible(false)?;
        let children = root.cast::<IPanel>()?.Children()?;
        children.Append(&grid.cast::<UIElement>()?)?;
        children.Append(&empty.cast::<UIElement>()?)?;

        let fill = {
            let state = state.clone();
            list.ContainerContentChanging(move |_, args| {
                let Ok(args) = args.ok() else { return };
                if args.InRecycleQueue().unwrap_or(true) {
                    return;
                }
                let tiles = state.tiles.borrow();
                let index = args.ItemIndex().unwrap_or(-1);
                if let (Some(tile), Ok(container)) = (
                    usize::try_from(index)
                        .ok()
                        .and_then(|index| tiles.tiles.get(index)),
                    args.ItemContainer(),
                ) {
                    if let Ok(root) = container
                        .cast::<IContentControl>()
                        .and_then(|content| content.ContentTemplateRoot())
                        .and_then(|root| root.cast::<Grid>())
                    {
                        check(fill_tile(&root, tile, &tiles, &state), "fill a tile");
                    }
                }
                let _ = args.SetHandled(true);
            })?
        };
        let clicked = {
            let state = state.clone();
            list.ItemClick(move |_, args| {
                let key = args
                    .ok()
                    .ok()
                    .and_then(|args| args.ClickedItem().ok())
                    .and_then(|item| xaml::unboxed(&item));
                let Some(key) = key else { return };
                let pressable = state
                    .tiles
                    .borrow()
                    .tiles
                    .iter()
                    .any(|tile| tile.key == key && tile.pressable);
                if pressable {
                    (state.post)(UiEvent::Node {
                        id: state.id,
                        event: Event::TilePressed(key),
                    });
                }
            })?
        };
        // Tiles share each row's width: as many as fit at their least width.
        let resized = {
            let state = state.clone();
            let control = grid.clone();
            grid.fe().SizeChanged(move |_, args| {
                if let Some(size) = args.ok().ok().and_then(|args| args.NewSize().ok()) {
                    check(
                        size_tiles(&control, &state.tiles.borrow(), f64::from(size.width)),
                        "size the tiles",
                    );
                }
            })?
        };
        let host = Self {
            root,
            grid,
            empty,
            state,
            _events: vec![fill, clicked, resized],
        };
        host.reload(props)?;
        host.show_empty(props)?;
        Ok(host)
    }

    pub fn element(&self) -> FrameworkElement {
        self.root.cast().expect("a grid is a framework element")
    }

    pub fn update(&self, props: &Tiles) -> Result<()> {
        let old = self.state.tiles.replace(props.clone());
        if old.min_width != props.min_width || old.height != props.height {
            size_tiles(&self.grid, props, self.grid.fe().ActualWidth()?)?;
        }
        let items = self.grid.cast::<IItemsControl>()?.Items()?;
        let changes = if old.check != props.check || old.test_label != props.test_label {
            KeyedChanges::Reload
        } else {
            props.tile_changes(&old)
        };
        match changes {
            KeyedChanges::None => {}
            KeyedChanges::Edit {
                removed,
                inserted,
                changed,
            } => {
                for index in removed.iter().rev() {
                    items.RemoveAt(*index as u32)?;
                }
                for index in &inserted {
                    items.InsertAt(*index as u32, &xaml::boxed(&props.tiles[*index].key)?)?;
                }
                let mapping = self.grid.cast::<IItemContainerMapping>()?;
                for index in changed {
                    let Ok(container) = mapping.ContainerFromIndex(index as i32) else {
                        continue;
                    };
                    if let Ok(root) = container
                        .cast::<IContentControl>()
                        .and_then(|content| content.ContentTemplateRoot())
                        .and_then(|root| root.cast::<Grid>())
                    {
                        fill_tile(&root, &props.tiles[index], props, &self.state)?;
                    }
                }
            }
            KeyedChanges::Reload => self.reload(props)?,
        }
        self.show_empty(props)
    }

    fn reload(&self, props: &Tiles) -> Result<()> {
        super::table::keeping_offset(&self.grid, || {
            let items = self.grid.cast::<IItemsControl>()?.Items()?;
            items.Clear()?;
            for tile in props.tiles.iter() {
                items.Append(&xaml::boxed(&tile.key)?)?;
            }
            Ok(())
        })
    }

    fn show_empty(&self, props: &Tiles) -> Result<()> {
        let empty = props.tiles.is_empty();
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
}

fn size_tiles(grid: &GridView, tiles: &Tiles, width: f64) -> Result<()> {
    let Ok(panel) = grid
        .cast::<IItemsControl>()?
        .ItemsPanelRoot()
        .and_then(|panel| panel.cast::<IItemsWrapGrid>())
    else {
        return Ok(());
    };
    if width <= 0.0 {
        return Ok(());
    }
    // Each tile's slot includes the spacing after it, which the grid's
    // width takes in beyond the page's edge. The grid view's scroll viewer
    // keeps its vertical scroll bar's width from the panel.
    let width = width - SCROLL_BAR;
    let slot = tiles.min_width + SPACING;
    let across = (width / slot).floor().max(1.0);
    panel.SetItemWidth((width / across).floor())?;
    panel.SetItemHeight(tiles.height + SPACING)
}

/// A tile's title (with the check mark of the selected one) over a line of
/// what it is, a detail, a mark and a value, which is a test button on a
/// testable tile.
fn fill_tile(root: &Grid, tile: &Tile, grid: &Tiles, state: &Rc<State>) -> Result<()> {
    let edge = if tile.selected { SELECTED_EDGE } else { EDGE };
    root.fe().SetStyle(&xaml::style(
        "Grid",
        None,
        &[
            (
                "Background",
                xaml::theme("CardBackgroundFillColorDefaultBrush"),
            ),
            (
                "BorderBrush",
                xaml::theme(if tile.selected {
                    "AccentFillColorDefaultBrush"
                } else {
                    "CardStrokeColorDefaultBrush"
                }),
            ),
        ],
    )?)?;
    root.SetBorderThickness(xaml::uniform(edge))?;
    root.SetCornerRadius(xaml::corners(8.0))?;
    // The wider edge takes from the padding, so the content stays put.
    root.SetPadding(xaml::thickness(INSET - edge + EDGE, 10.0 - edge + EDGE))?;
    root.SetRowSpacing(4.0)?;
    root.fe().SetHeight(grid.height)?;
    let rows = root.RowDefinitions()?;
    if rows.Size()? == 0 {
        for length in [xaml::star(), xaml::auto()] {
            let row = RowDefinition::new()?;
            row.SetHeight(length)?;
            rows.Append(&row)?;
        }
    }
    let children = root.cast::<IPanel>()?.Children()?;
    children.Clear()?;
    let head = Grid::new()?;
    head.SetColumnSpacing(6.0)?;
    for length in [xaml::star(), xaml::auto()] {
        let column = ColumnDefinition::new()?;
        column.SetWidth(length)?;
        head.ColumnDefinitions()?.Append(&column)?;
    }
    head.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
    let title = label(&tile.title, TextStyle::Heading, Tone::Default)?;
    title.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
    {
        // A title too wide for its tile is cut, and the tile's tooltip then
        // leads with it, as it does on macOS. The handler lives as long as
        // the title, which a refill replaces.
        let (surface, full, tooltip) = (root.clone(), tile.title.clone(), tile.tooltip.clone());
        let _ = title
            .IsTextTrimmedChanged(move |block, _| {
                let cut = block
                    .ok()
                    .ok()
                    .and_then(|block| block.IsTextTrimmed().ok())
                    .unwrap_or(false);
                check(
                    set_tile_tooltip(&surface, cut.then_some(full.as_str()), tooltip.as_deref()),
                    "a tile's tooltip",
                );
            })?
            .into_token();
    }
    head.cast::<IPanel>()?
        .Children()?
        .Append(&title.cast::<UIElement>()?)?;
    if tile.selected && grid.check {
        let mark = FontIcon::new()?;
        mark.fe().SetStyle(&xaml::icon_style(Tone::Accent, 12.0)?)?;
        mark.SetGlyph(xaml::glyph(Icon::Check))?;
        mark.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
        Grid::SetColumn(&mark, 1)?;
        head.cast::<IPanel>()?
            .Children()?
            .Append(&mark.cast::<UIElement>()?)?;
    }
    children.Append(&head.cast::<UIElement>()?)?;

    let line = Grid::new()?;
    line.SetColumnSpacing(6.0)?;
    Grid::SetRow(&line, 1)?;
    for length in [xaml::auto(), xaml::star(), xaml::auto(), xaml::auto()] {
        let column = ColumnDefinition::new()?;
        column.SetWidth(length)?;
        line.ColumnDefinitions()?.Append(&column)?;
    }
    let parts = line.cast::<IPanel>()?.Children()?;
    parts.Append(&label(&tile.kind, TextStyle::Caption, Tone::Muted)?.cast::<UIElement>()?)?;
    if let Some(detail) = &tile.detail {
        let detail = label(&format!("· {detail}"), TextStyle::Caption, Tone::Faint)?;
        detail
            .fe()
            .SetVerticalAlignment(VerticalAlignment::Center)?;
        Grid::SetColumn(&detail, 1)?;
        parts.Append(&detail.cast::<UIElement>()?)?;
    }
    if let Some(mark) = tile.mark {
        let icon = mark_icon(mark)?;
        Grid::SetColumn(&icon, 2)?;
        parts.Append(&icon.cast::<UIElement>()?)?;
    }
    let value = if tile.testable {
        Some(test_button(tile, grid, state)?.cast::<UIElement>()?)
    } else {
        value_view(&tile.value)?
    };
    if let Some(value) = value {
        Grid::SetColumn(&xaml::as_element(&value)?, 3)?;
        parts.Append(&value)?;
    }
    children.Append(&line.cast::<UIElement>()?)?;
    root.ui().SetOpacity(if tile.dimmed { 0.55 } else { 1.0 })?;
    set_tile_tooltip(root, None, tile.tooltip.as_deref())?;
    Ok(())
}

/// What a tile tells about itself: its title while the title is cut, then
/// what the interface gave it.
fn set_tile_tooltip(root: &Grid, title: Option<&str>, tooltip: Option<&str>) -> Result<()> {
    let lines: Vec<&str> = title.into_iter().chain(tooltip).collect();
    if lines.is_empty() {
        ToolTipService::SetToolTip(root, None::<&windows_core::IInspectable>)
    } else {
        ToolTipService::SetToolTip(root, &xaml::boxed(&lines.join("\n"))?)
    }
}

/// The tile's value: its text, or a ring while it is measured.
fn value_view(value: &TileValue) -> Result<Option<UIElement>> {
    Ok(match value {
        TileValue::None => None,
        TileValue::Text { text, tone } => Some(label(text, TextStyle::Caption, *tone)?.cast()?),
        TileValue::Progress => {
            let ring = ProgressRing::new()?;
            ring.SetIsActive(true)?;
            ring.fe().SetWidth(12.0)?;
            ring.fe().SetHeight(12.0)?;
            ring.fe().SetMinWidth(12.0)?;
            ring.fe().SetMinHeight(12.0)?;
            Some(ring.cast()?)
        }
    })
}

/// A testable tile's value as a subtle button that reports a test: the
/// value, the ring while testing, or the test symbol before the first
/// result. Its content lines up with the title's end, its padding beyond.
fn test_button(tile: &Tile, grid: &Tiles, state: &Rc<State>) -> Result<Button> {
    let button = Button::new()?;
    button
        .fe()
        .SetStyle(&xaml::resource::<super::bindings::Style>(
            "SubtleButtonStyle",
        )?)?;
    let control = button.cast::<IControl>()?;
    control.SetPadding(xaml::thickness(TEST_PADDING, 1.0))?;
    control.SetCornerRadius(xaml::corners(4.0))?;
    button.fe().SetMinWidth(0.0)?;
    button.fe().SetMinHeight(0.0)?;
    button.fe().SetMargin(Thickness {
        left: 0.0,
        top: -2.0,
        right: -TEST_PADDING,
        bottom: -2.0,
    })?;
    button
        .fe()
        .SetVerticalAlignment(VerticalAlignment::Center)?;
    let content: UIElement = match value_view(&tile.value)? {
        Some(view) => view,
        None => {
            let symbol = mark_icon(Icon::Zap)?;
            symbol.cast()?
        }
    };
    button.cast::<IContentControl>()?.SetContent(&content)?;
    ToolTipService::SetToolTip(&button, &xaml::boxed(&grid.test_label)?)?;
    AutomationProperties::SetName(&button, &grid.test_label)?;
    let (id, post, key) = (state.id, state.post, tile.key.clone());
    // The handler lives as long as the button, which a refill replaces.
    let _ = button
        .cast::<IButtonBase>()?
        .Click(move |_, _| {
            post(UiEvent::Node {
                id,
                event: Event::TileTested(key.clone()),
            })
        })?
        .into_token();
    Ok(button)
}

fn mark_icon(icon: Icon) -> Result<FontIcon> {
    let view = FontIcon::new()?;
    view.fe().SetStyle(&xaml::icon_style(Tone::Muted, 11.0)?)?;
    view.SetGlyph(xaml::glyph(icon))?;
    view.fe().SetVerticalAlignment(VerticalAlignment::Center)?;
    Ok(view)
}
