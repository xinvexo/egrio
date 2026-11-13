//! The tile grid as a `GtkGridView`: as many tiles to a row as fit at
//! their least width, sharing the row's width. The grid view counts
//! columns by its items' least width when its horizontal scroll policy is
//! `minimum` and stretches the columns to fill the row (`gtkgridview.c`,
//! `gtk_grid_view_compute_n_columns`). It builds widgets only for the
//! tiles it shows, like the table, and a changed tile on screen takes its
//! new content in place. A tile is drawn as a card; a pressable one takes
//! a click, or Return and Space while it has the keyboard focus. The
//! selected tile has the accent edge, and a check mark after its title
//! where the grid checks its selection. A testable tile's value is a
//! button of its own at the end of its second line, the test symbol before
//! its first result, which reports a test instead of a press.
//!
//! The space between tiles is their cells' padding, which also lies around
//! the grid's edges; the grid reaches that far past its own bounds, so the
//! tiles' edges line up with the page around it.

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{gio, glib, graphene, gsk};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{Icon, KeyedChanges, TextStyle, Tile, TileValue, Tiles, Tone};
use egrio_ui::reconcile::NodeId;

use super::style;
use super::widgets::Post;

/// The padding of a tile's cell (`gridview.egrio-tiles > child` in the
/// stylesheet): half the space between two tiles.
const CELL_PADDING: i32 = 5;
/// Space inside a tile's edges.
const INSET: i32 = 14;
/// Space around the test button's content, which its highlight covers.
const TEST_PADDING: i32 = 4;
/// The height of what the test button shows: its value, the test symbol or
/// the spinner.
const VALUE_HEIGHT: i32 = 16;

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct TileCard {
        pub parts: OnceCell<super::Parts>,
        /// The key of the tile the card shows.
        pub key: RefCell<String>,
        /// The tile's own help, which leads with its title while cut.
        pub help: RefCell<Option<String>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for TileCard {
        const NAME: &'static str = "EgrioTile";
        type Type = super::TileCard;
        type ParentType = gtk::Box;
    }

    impl ObjectImpl for TileCard {}
    impl WidgetImpl for TileCard {}
    impl BoxImpl for TileCard {}

    /// Holds the grid a cell's padding past its own edges.
    #[derive(Default)]
    pub struct Bleed;

    #[glib::object_subclass]
    impl ObjectSubclass for Bleed {
        const NAME: &'static str = "EgrioTilesBleed";
        type Type = super::Bleed;
        type ParentType = gtk::Widget;
    }

    impl ObjectImpl for Bleed {
        fn dispose(&self) {
            while let Some(child) = self.obj().first_child() {
                child.unparent();
            }
        }
    }

    impl WidgetImpl for Bleed {
        fn measure(&self, orientation: gtk::Orientation, for_size: i32) -> (i32, i32, i32, i32) {
            let Some(child) = self.obj().first_child() else {
                return (0, 0, -1, -1);
            };
            let for_size = if for_size < 0 {
                for_size
            } else {
                for_size + 2 * CELL_PADDING
            };
            let (minimum, natural, _, _) = child.measure(orientation, for_size);
            let less = |size: i32| (size - 2 * CELL_PADDING).max(0);
            (less(minimum), less(natural), -1, -1)
        }

        fn size_allocate(&self, width: i32, height: i32, _baseline: i32) {
            if let Some(child) = self.obj().first_child() {
                let offset = -CELL_PADDING as f32;
                child.allocate(
                    width + 2 * CELL_PADDING,
                    height + 2 * CELL_PADDING,
                    -1,
                    Some(gsk::Transform::new().translate(&graphene::Point::new(offset, offset))),
                );
            }
        }
    }
}

glib::wrapper! {
    pub struct TileCard(ObjectSubclass<imp::TileCard>)
        @extends gtk::Box, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::Orientable;
}

glib::wrapper! {
    pub struct Bleed(ObjectSubclass<imp::Bleed>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl Bleed {
    fn new(child: &impl IsA<gtk::Widget>) -> Self {
        let bleed: Self = glib::Object::new();
        child.set_parent(&bleed);
        bleed
    }
}

/// A tile's widgets: its title and check mark over a line of what it is, a
/// detail, a mark and its test button with the value.
pub struct Parts {
    title: gtk::Label,
    check: gtk::Image,
    kind: gtk::Label,
    detail: gtk::Label,
    mark: gtk::Image,
    test: gtk::Button,
    value: gtk::Label,
    zap: gtk::Image,
    spinner: gtk::Spinner,
}

impl TileCard {
    /// A card that reports a press of its test button to `tested`, with the
    /// key of the tile it shows then.
    fn new(tested: impl Fn(String) + 'static) -> Self {
        let card: Self = glib::Object::builder()
            .property("orientation", gtk::Orientation::Vertical)
            .property("spacing", 2)
            .build();
        card.add_css_class("card");
        let title = gtk::Label::new(None);
        title.set_xalign(0.0);
        title.set_ellipsize(gtk::pango::EllipsizeMode::End);
        title.set_single_line_mode(true);
        title.set_hexpand(true);
        style::set_text_style(&title, TextStyle::Heading, Tone::Default);
        let check = style::image(Icon::Check, Tone::Accent, 12);
        let head = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        head.append(&title);
        head.append(&check);
        let kind = style::label("", TextStyle::Caption, Tone::Muted);
        let detail = style::label("", TextStyle::Caption, Tone::Faint);
        let mark = style::image(Icon::Link, Tone::Muted, 12);
        let value = style::label("", TextStyle::Caption, Tone::Default);
        value.add_css_class("numeric");
        let zap = style::image(Icon::Zap, Tone::Muted, 12);
        let spinner = gtk::Spinner::new();
        spinner.add_css_class("egrio-small");
        // One height whatever it shows, so a test starting or ending moves
        // neither line.
        let shows = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        shows.set_size_request(-1, VALUE_HEIGHT);
        for part in [
            value.upcast_ref::<gtk::Widget>(),
            zap.upcast_ref(),
            spinner.upcast_ref(),
        ] {
            part.set_valign(gtk::Align::Center);
            shows.append(part);
        }
        let test = gtk::Button::new();
        test.add_css_class("egrio-tile-test");
        test.set_child(Some(&shows));
        // The kind, the detail and the mark lead the line; the value ends it.
        let room = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        room.set_hexpand(true);
        let line = gtk::Box::new(gtk::Orientation::Horizontal, 6);
        line.append(&kind);
        line.append(&detail);
        line.append(&mark);
        line.append(&room);
        line.append(&test);
        // The two lines meet at the middle; the value's text ends where the
        // title does, its button's padding beyond.
        head.set_margin_start(INSET);
        head.set_margin_end(INSET);
        head.set_margin_top(6);
        head.set_vexpand(true);
        head.set_valign(gtk::Align::End);
        line.set_margin_start(INSET);
        line.set_margin_end(INSET - TEST_PADDING);
        line.set_margin_bottom(6);
        line.set_vexpand(true);
        line.set_valign(gtk::Align::Start);
        card.append(&head);
        card.append(&line);
        {
            let card = card.downgrade();
            test.connect_clicked(move |_| {
                if let Some(card) = card.upgrade() {
                    tested(card.imp().key.borrow().clone());
                }
            });
        }
        // The tile's hover light gives way to the test button's.
        let motion = gtk::EventControllerMotion::new();
        {
            let card = card.downgrade();
            motion.connect_enter(move |_, _, _| {
                if let Some(card) = card.upgrade() {
                    card.add_css_class("egrio-over-test");
                }
            });
        }
        {
            let card = card.downgrade();
            motion.connect_leave(move |_| {
                if let Some(card) = card.upgrade() {
                    card.remove_css_class("egrio-over-test");
                }
            });
        }
        test.add_controller(motion);
        card.set_has_tooltip(true);
        card.connect_query_tooltip(|card, _, _, _, tooltip| {
            let Some(parts) = card.imp().parts.get() else {
                return false;
            };
            let help = card.imp().help.borrow();
            let lines: Vec<String> = style::is_cut(&parts.title)
                .then(|| parts.title.text().to_string())
                .into_iter()
                .chain(help.iter().cloned())
                .collect();
            if lines.is_empty() {
                return false;
            }
            tooltip.set_text(Some(&lines.join("\n")));
            true
        });
        let _ = card.imp().parts.set(Parts {
            title,
            check,
            kind,
            detail,
            mark,
            test,
            value,
            zap,
            spinner,
        });
        card
    }

    fn show(&self, tile: &Tile, tiles: &Tiles) {
        self.set_size_request(tiles.min_width.round() as i32, tiles.height.round() as i32);
        *self.imp().key.borrow_mut() = tile.key.clone();
        *self.imp().help.borrow_mut() = tile.tooltip.clone();
        let Some(parts) = self.imp().parts.get() else {
            return;
        };
        parts.title.set_text(&tile.title);
        parts.check.set_visible(tile.selected && tiles.check);
        parts.kind.set_text(&tile.kind);
        match &tile.detail {
            Some(detail) => {
                parts.detail.set_text(&format!("· {detail}"));
                parts.detail.set_visible(true);
            }
            None => {
                parts.detail.set_text("");
                parts.detail.set_visible(false);
            }
        }
        parts.mark.set_visible(tile.mark.is_some());
        if let Some(mark) = tile.mark {
            parts.mark.set_icon_name(Some(style::icon_name(mark)));
        }
        let text = match &tile.value {
            TileValue::Text { text, tone } => {
                style::set_tone(&parts.value, *tone);
                Some(text.as_str())
            }
            TileValue::None | TileValue::Progress => None,
        };
        parts.value.set_visible(text.is_some());
        parts.value.set_text(text.unwrap_or(""));
        let progress = tile.value == TileValue::Progress;
        parts.spinner.set_visible(progress);
        parts.spinner.set_spinning(progress);
        let symbol = tile.testable && tile.value == TileValue::None;
        parts.zap.set_visible(symbol);
        // The value is a button while the tile can be tested; otherwise a
        // click on it is the tile's. It keeps its height when it shows
        // nothing, so the tiles of a row line up.
        parts.test.set_can_target(tile.testable);
        parts.test.set_can_focus(tile.testable);
        parts
            .test
            .set_tooltip_text(tile.testable.then_some(tiles.test_label.as_str()));
        parts
            .test
            .update_property(&[gtk::accessible::Property::Label(&tiles.test_label)]);
        if tile.testable {
            parts.test.add_css_class("egrio-testable");
        } else {
            parts.test.remove_css_class("egrio-testable");
            self.remove_css_class("egrio-over-test");
        }
        for (class, wanted) in [
            ("egrio-pressable", tile.pressable),
            ("egrio-selected", tile.selected),
            ("egrio-dimmed", tile.dimmed),
        ] {
            if wanted {
                self.add_css_class(class);
            } else {
                self.remove_css_class(class);
            }
        }
    }
}

struct State {
    id: NodeId,
    post: Post,
    tiles: RefCell<Tiles>,
    places: RefCell<HashMap<String, usize>>,
    store: gio::ListStore,
    /// The cards showing each tile now.
    bound: RefCell<HashMap<String, Vec<glib::WeakRef<TileCard>>>>,
}

impl State {
    fn tile(&self, key: &str) -> Option<Tile> {
        let place = *self.places.borrow().get(key)?;
        self.tiles.borrow().tiles.get(place).cloned()
    }

    fn send(&self, event: Event) {
        (self.post)(UiEvent::Node { id: self.id, event });
    }
}

pub struct TilesHost {
    root: Bleed,
    empty: gtk::Label,
    state: Rc<State>,
}

impl TilesHost {
    pub fn new(id: NodeId, props: &Tiles, post: Post) -> Self {
        let state = Rc::new(State {
            id,
            post,
            tiles: RefCell::new(props.clone()),
            places: RefCell::new(HashMap::new()),
            store: gio::ListStore::new::<glib::BoxedAnyObject>(),
            bound: RefCell::new(HashMap::new()),
        });
        let factory = gtk::SignalListItemFactory::new();
        {
            let weak = Rc::downgrade(&state);
            factory.connect_setup(move |_, item| {
                let Some(item) = item.downcast_ref::<gtk::ListItem>() else {
                    return;
                };
                let weak = weak.clone();
                item.set_child(Some(&TileCard::new(move |key| {
                    let Some(state) = weak.upgrade() else { return };
                    if state.tile(&key).is_some_and(|tile| tile.testable) {
                        state.send(Event::TileTested(key));
                    }
                })));
            });
        }
        {
            let weak = Rc::downgrade(&state);
            factory.connect_bind(move |_, item| {
                let (Some(state), Some(item)) =
                    (weak.upgrade(), item.downcast_ref::<gtk::ListItem>())
                else {
                    return;
                };
                let (Some(card), Some(key)) = (card_of(item), item_key(item)) else {
                    return;
                };
                if let Some(tile) = state.tile(&key) {
                    card.show(&tile, &state.tiles.borrow());
                    item.set_activatable(tile.pressable);
                }
                state
                    .bound
                    .borrow_mut()
                    .entry(key)
                    .or_default()
                    .push(card.downgrade());
            });
        }
        {
            let weak = Rc::downgrade(&state);
            factory.connect_unbind(move |_, item| {
                let (Some(state), Some(item)) =
                    (weak.upgrade(), item.downcast_ref::<gtk::ListItem>())
                else {
                    return;
                };
                let (Some(card), Some(key)) = (card_of(item), item_key(item)) else {
                    return;
                };
                let mut bound = state.bound.borrow_mut();
                if let Some(cards) = bound.get_mut(&key) {
                    cards.retain(|other| other.upgrade().is_some_and(|other| other != card));
                    if cards.is_empty() {
                        bound.remove(&key);
                    }
                }
            });
        }
        let selection = gtk::NoSelection::new(Some(state.store.clone()));
        let grid = gtk::GridView::new(Some(selection), Some(factory));
        grid.add_css_class("egrio-tiles");
        grid.set_max_columns(64);
        grid.set_single_click_activate(true);
        grid.set_hscroll_policy(gtk::ScrollablePolicy::Minimum);
        {
            let weak = Rc::downgrade(&state);
            grid.connect_activate(move |_, position| {
                let Some(state) = weak.upgrade() else { return };
                let Some(key) = state
                    .store
                    .item(position)
                    .and_then(|object| key_of(&object))
                else {
                    return;
                };
                if state.tile(&key).is_some_and(|tile| tile.pressable) {
                    state.send(Event::TilePressed(key));
                }
            });
        }
        let scroll = gtk::ScrolledWindow::new();
        scroll.set_policy(gtk::PolicyType::Never, gtk::PolicyType::Automatic);
        scroll.set_child(Some(&grid));
        let empty = style::label("", TextStyle::Body, Tone::Muted);
        empty.set_halign(gtk::Align::Center);
        empty.set_valign(gtk::Align::Center);
        empty.set_can_target(false);
        let overlay = gtk::Overlay::new();
        overlay.set_child(Some(&scroll));
        overlay.add_overlay(&empty);
        let host = Self {
            root: Bleed::new(&overlay),
            empty,
            state,
        };
        host.reload(props);
        host.show_empty(props);
        host
    }

    pub fn widget(&self) -> gtk::Widget {
        self.root.clone().upcast()
    }

    pub fn update(&self, props: &Tiles) {
        let old = self.state.tiles.replace(props.clone());
        match props.tile_changes(&old) {
            KeyedChanges::None => {}
            KeyedChanges::Edit {
                removed,
                inserted,
                changed,
            } => {
                self.index(props);
                for index in removed.iter().rev() {
                    self.state.store.remove(*index as u32);
                }
                for index in &inserted {
                    self.state.store.insert(
                        *index as u32,
                        &glib::BoxedAnyObject::new(props.tiles[*index].key.clone()),
                    );
                }
                let bound = self.state.bound.borrow().clone();
                for index in changed {
                    let tile = &props.tiles[index];
                    for card in bound.get(&tile.key).into_iter().flatten() {
                        if let Some(card) = card.upgrade() {
                            card.show(tile, props);
                        }
                    }
                }
            }
            KeyedChanges::Reload => self.reload(props),
        }
        // What every card shows from the grid: its size, the check mark and
        // the test button's help.
        if old.min_width != props.min_width
            || old.height != props.height
            || old.check != props.check
            || old.test_label != props.test_label
        {
            let bound = self.state.bound.borrow().clone();
            for (key, cards) in bound {
                if let Some(tile) = self.state.tile(&key) {
                    for card in cards.iter().filter_map(glib::WeakRef::upgrade) {
                        card.show(&tile, props);
                    }
                }
            }
        }
        self.show_empty(props);
    }

    fn index(&self, props: &Tiles) {
        *self.state.places.borrow_mut() = props
            .tiles
            .iter()
            .enumerate()
            .map(|(place, tile)| (tile.key.clone(), place))
            .collect();
    }

    fn reload(&self, props: &Tiles) {
        self.index(props);
        let tiles: Vec<glib::BoxedAnyObject> = props
            .tiles
            .iter()
            .map(|tile| glib::BoxedAnyObject::new(tile.key.clone()))
            .collect();
        self.state
            .store
            .splice(0, self.state.store.n_items(), &tiles);
    }

    fn show_empty(&self, props: &Tiles) {
        let empty = props.tiles.is_empty();
        self.empty
            .set_text(props.empty.as_deref().filter(|_| empty).unwrap_or(""));
        self.empty.set_visible(empty && props.empty.is_some());
    }
}

fn card_of(item: &gtk::ListItem) -> Option<TileCard> {
    item.child()?.downcast::<TileCard>().ok()
}

fn key_of(object: &glib::Object) -> Option<String> {
    let boxed = object.downcast_ref::<glib::BoxedAnyObject>()?;
    let key = boxed.borrow::<String>();
    Some(key.clone())
}

fn item_key(item: &gtk::ListItem) -> Option<String> {
    key_of(&item.item()?)
}
