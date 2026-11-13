//! A table cell's widgets, kept by the shape of what they show: binding a
//! row whose cell has the same kind again only updates the text, colors and
//! images, so scrolling through thousands of rows builds no widgets once the
//! visible rows have theirs.

use std::cell::{Cell as StdCell, RefCell};
use std::collections::HashMap;
use std::sync::Arc;

use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

use egrio_ui::node::{Badge, Cell, ColumnAlign, Icon, Image, TextStyle, Tone};

use super::style;
use super::widgets::{badge_label, style_badge};

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct CellView {
        pub parts: RefCell<Parts>,
        /// The table column the cell shows.
        pub column: StdCell<usize>,
        /// The list item the cell belongs to, which knows the row's place.
        pub item: glib::WeakRef<gtk::ListItem>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for CellView {
        const NAME: &'static str = "EgrioCell";
        type Type = super::CellView;
        type ParentType = gtk::Box;
    }

    impl ObjectImpl for CellView {}
    impl WidgetImpl for CellView {}
    impl BoxImpl for CellView {}
}

glib::wrapper! {
    pub struct CellView(ObjectSubclass<imp::CellView>)
        @extends gtk::Box, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::Orientable;
}

/// The widgets of one shape of cell, each under one root widget.
#[derive(Default)]
pub enum Parts {
    #[default]
    Empty,
    Text(gtk::Label),
    Badge(gtk::Label),
    Status {
        line: gtk::Box,
        dot: gtk::Box,
        label: gtk::Label,
    },
    Process {
        line: gtk::Box,
        image: gtk::Image,
        label: gtk::Label,
    },
    Number(gtk::Label),
    TwoLine {
        line: gtk::Box,
        image: gtk::Image,
        title: gtk::Label,
        detail: gtk::Label,
        trailing: gtk::Label,
    },
    Inline {
        line: gtk::Box,
        items: Vec<Parts>,
    },
}

impl CellView {
    pub fn new(column: usize) -> Self {
        let cell: Self = glib::Object::builder()
            .property("orientation", gtk::Orientation::Horizontal)
            .build();
        cell.imp().column.set(column);
        cell.set_valign(gtk::Align::Fill);
        cell
    }

    pub fn column(&self) -> usize {
        self.imp().column.get()
    }

    pub fn set_item(&self, item: &gtk::ListItem) {
        self.imp().item.set(Some(item));
    }

    /// The place of the row the cell shows now.
    #[cfg(feature = "test-control")]
    pub fn position(&self) -> Option<u32> {
        let item = self.imp().item.upgrade()?;
        item.item().is_some().then(|| item.position())
    }

    /// Shows `cell`, reusing the widgets it has when the shape is the same.
    pub fn render(&self, cell: &Cell, align: ColumnAlign, wrap: bool) {
        let mut parts = self.imp().parts.borrow_mut();
        if !same_shape(&parts, cell) {
            if let Some(root) = parts.root() {
                self.remove(&root);
            }
            *parts = build(cell);
            if let Some(root) = parts.root() {
                root.set_hexpand(true);
                root.set_valign(gtk::Align::Center);
                self.append(&root);
            }
        }
        update(&mut parts, cell, align, wrap);
    }
}

impl Parts {
    fn root(&self) -> Option<gtk::Widget> {
        Some(match self {
            Parts::Empty => return None,
            Parts::Text(label) | Parts::Badge(label) | Parts::Number(label) => {
                label.clone().upcast()
            }
            Parts::Status { line, .. }
            | Parts::Process { line, .. }
            | Parts::TwoLine { line, .. }
            | Parts::Inline { line, .. } => line.clone().upcast(),
        })
    }
}

fn same_shape(parts: &Parts, cell: &Cell) -> bool {
    match (parts, cell) {
        (Parts::Text(_), Cell::Text { .. })
        | (Parts::Badge(_), Cell::Badge { .. })
        | (Parts::Status { .. }, Cell::Status { .. })
        | (Parts::Process { .. }, Cell::Process { .. })
        | (Parts::Number(_), Cell::Number(_))
        | (Parts::TwoLine { .. }, Cell::TwoLine { .. }) => true,
        (Parts::Inline { items, .. }, Cell::Inline(cells)) => {
            items.len() == cells.len()
                && items
                    .iter()
                    .zip(cells)
                    .all(|(item, cell)| same_shape(item, cell))
        }
        _ => false,
    }
}

fn line(spacing: i32) -> gtk::Box {
    let line = gtk::Box::new(gtk::Orientation::Horizontal, spacing);
    line.set_valign(gtk::Align::Center);
    line
}

fn build(cell: &Cell) -> Parts {
    match cell {
        Cell::Text { .. } => {
            let label = gtk::Label::new(None);
            style::help_when_cut(&label);
            Parts::Text(label)
        }
        Cell::Badge { text, tone } => {
            let label = badge_label(&Badge {
                text: text.clone(),
                tone: *tone,
            });
            label.set_halign(gtk::Align::Start);
            label.set_hexpand(false);
            Parts::Badge(label)
        }
        Cell::Status { .. } => {
            let line = line(6);
            let dot = gtk::Box::new(gtk::Orientation::Horizontal, 0);
            dot.add_css_class("egrio-dot");
            dot.set_valign(gtk::Align::Center);
            let label = style::label("", TextStyle::Body, Tone::Default);
            line.append(&dot);
            line.append(&label);
            Parts::Status { line, dot, label }
        }
        Cell::Process { .. } => {
            let line = line(6);
            let image = gtk::Image::new();
            image.set_pixel_size(16);
            let label = style::label("", TextStyle::Body, Tone::Default);
            line.append(&image);
            line.append(&label);
            Parts::Process { line, image, label }
        }
        Cell::Number(_) => {
            let label = style::label("", TextStyle::Caption, Tone::Muted);
            label.add_css_class("numeric");
            label.set_xalign(1.0);
            Parts::Number(label)
        }
        Cell::TwoLine { .. } => {
            let line = line(10);
            let image = gtk::Image::new();
            image.set_pixel_size(20);
            let lines = gtk::Box::new(gtk::Orientation::Vertical, 1);
            lines.set_hexpand(true);
            lines.set_valign(gtk::Align::Center);
            let title = style::label("", TextStyle::Body, Tone::Default);
            let detail = style::label("", TextStyle::Caption, Tone::Muted);
            lines.append(&title);
            lines.append(&detail);
            let trailing = style::label("", TextStyle::Caption, Tone::Muted);
            trailing.add_css_class("numeric");
            line.append(&image);
            line.append(&lines);
            line.append(&trailing);
            Parts::TwoLine {
                line,
                image,
                title,
                detail,
                trailing,
            }
        }
        Cell::Inline(cells) => {
            let line = line(6);
            let items: Vec<Parts> = cells.iter().map(build).collect();
            for (index, item) in items.iter().enumerate() {
                if let Some(root) = item.root() {
                    // The first cell takes the room the tags leave, which
                    // puts them at the column's end.
                    root.set_hexpand(index == 0);
                    line.append(&root);
                }
            }
            Parts::Inline { line, items }
        }
    }
}

fn set_text(label: &gtk::Label, text: &str) {
    if label.text() != text {
        label.set_text(text);
    }
}

fn update(parts: &mut Parts, cell: &Cell, align: ColumnAlign, wrap: bool) {
    match (parts, cell) {
        (Parts::Text(label), Cell::Text { text, tone, mono }) => {
            set_text(label, text);
            style::set_text_style(
                label,
                if *mono {
                    TextStyle::Mono
                } else {
                    TextStyle::Body
                },
                *tone,
            );
            label.set_xalign(match align {
                ColumnAlign::Leading => 0.0,
                ColumnAlign::Trailing => 1.0,
            });
            if wrap {
                label.set_single_line_mode(false);
                label.set_ellipsize(gtk::pango::EllipsizeMode::None);
                label.set_wrap(true);
                label.set_wrap_mode(gtk::pango::WrapMode::WordChar);
                label.set_selectable(true);
            } else {
                label.set_wrap(false);
                label.set_single_line_mode(true);
                label.set_ellipsize(gtk::pango::EllipsizeMode::End);
            }
        }
        (Parts::Badge(label), Cell::Badge { text, tone }) => {
            style_badge(
                label,
                &Badge {
                    text: text.clone(),
                    tone: *tone,
                },
            );
            // A badge keeps its size at its column's side.
            label.set_halign(match align {
                ColumnAlign::Leading => gtk::Align::Start,
                ColumnAlign::Trailing => gtk::Align::End,
            });
        }
        (Parts::Status { dot, label, .. }, Cell::Status { text, tone }) => {
            style::set_tone(dot, *tone);
            set_text(label, text);
            style::set_tone(label, *tone);
        }
        (Parts::Process { image, label, .. }, Cell::Process { name, icon }) => {
            show_image(image, icon.as_ref(), Icon::App);
            set_text(label, name);
        }
        (Parts::Number(label), Cell::Number(value)) => set_text(label, value),
        (
            Parts::TwoLine {
                image,
                title,
                detail,
                trailing,
                ..
            },
            Cell::TwoLine {
                title: title_text,
                detail: detail_text,
                icon,
                fallback,
                trailing: trailing_text,
                trailing_tone,
            },
        ) => {
            show_image(image, icon.as_ref(), *fallback);
            set_text(title, title_text);
            set_text(detail, detail_text);
            set_text(trailing, trailing_text);
            style::set_tone(trailing, *trailing_tone);
        }
        (Parts::Inline { items, .. }, Cell::Inline(cells)) => {
            for (item, cell) in items.iter_mut().zip(cells) {
                update(item, cell, ColumnAlign::Leading, wrap);
            }
        }
        _ => {}
    }
}

/// An app's icon, or the fallback symbol without one.
fn show_image(view: &gtk::Image, image: Option<&Image>, fallback: Icon) {
    match image.and_then(texture) {
        Some(texture) => {
            view.set_paintable(Some(&texture));
            style::set_tone(view, Tone::Default);
        }
        None => {
            view.set_icon_name(Some(style::icon_name(fallback)));
            style::set_tone(view, Tone::Muted);
        }
    }
}

/// A decoded app icon with the PNG data it came from.
type Decoded = (Arc<[u8]>, gtk::gdk::Texture);

thread_local! {
    /// Decoded app icons by the identity of their PNG data, which the cache
    /// keeps so no other image takes the same address.
    static TEXTURES: RefCell<HashMap<usize, Decoded>> = RefCell::new(HashMap::new());
}

fn texture(image: &Image) -> Option<gtk::gdk::Texture> {
    let key = Arc::as_ptr(&image.0) as *const u8 as usize;
    if let Some((_, texture)) = TEXTURES.with(|textures| textures.borrow().get(&key).cloned()) {
        return Some(texture);
    }
    let texture = gtk::gdk::Texture::from_bytes(&glib::Bytes::from(&image.0[..]))
        .map_err(|error| log::debug!("decode an app icon: {error}"))
        .ok()?;
    TEXTURES.with(|textures| {
        textures
            .borrow_mut()
            .insert(key, (image.0.clone(), texture.clone()))
    });
    Some(texture)
}
