//! The message capsule at the start of the page's header bar, and the
//! message panel that grows out of it. The capsule is always there: a
//! small surface with the bell and the number of messages, which keep one
//! size and place in every state, so nothing jumps. With unread messages it
//! stays expanded into the free space before the switches, tinted by the
//! most severe of them and showing the newest one cut to one line, until
//! they are read. A click opens or closes the panel. The capsule floats in a
//! `GtkOverlay` over the header bar and the page, placed where a mark at the
//! bar's start is, so its width moves nothing; its surface lies under it in the same overlay and
//! is the panel's, so the panel grows out of the capsule and shrinks back
//! into it as one surface. The messages lie over the surface in a scrolled
//! window of their own, which cuts them off while the panel moves rather
//! than laying them out again. The capsule's width and the panel's growth
//! animate (`AdwTimedAnimation`), the tints and the panel's shadow through
//! CSS transitions.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::{gdk, glib, graphene};

use egrio_ui::backend::{MessagesButton, ToolbarAction, UiEvent, DRAWER_HEIGHT, DRAWER_WIDTH};
use egrio_ui::messages::Level;

use super::widgets::Post;

/// The capsule's height, which is also the open panel's head.
const HEIGHT: i32 = 26;
/// The capsule's ends, and the gaps inside it.
const PADDING: f64 = 9.0;
const BELL: i32 = 16;
const GAP: f64 = 5.0;
/// The widest the capsule gets: the panel's width.
const WIDEST: f64 = DRAWER_WIDTH;
/// The least space left between the capsule and the switches.
const CLEARANCE: f64 = 16.0;
/// The messages' distance from the header bar above them and their inset
/// from the panel's other edges, and the open panel's least distance from
/// the window's bottom edge.
const BELOW_BAR: f64 = 4.0;
const INSET: f64 = 16.0;
const MARGIN: f64 = 10.0;
/// How long the capsule and the panel take to change; they ease out, so
/// they come to rest softly.
const DURATION: u32 = 250;
const TINTS: [&str; 3] = ["error", "warning", "accent"];
const OPEN: &str = "egrio-open";

/// The capsule's widgets and what they show.
struct Parts {
    button: gtk::Button,
    count: gtk::Label,
    text: gtk::Label,
    /// The capsule's surface, which is the panel's.
    surface: gtk::Box,
    /// Over the surface, the messages, which it cuts off while the panel
    /// moves.
    scroller: gtk::ScrolledWindow,
    host: gtk::Box,
    shown: RefCell<Option<MessagesButton>>,
    /// The width the capsule has now, which the animation moves.
    width: Cell<f64>,
    /// The width it heads for.
    target: Cell<f64>,
    /// The most it may take, up to the switches; the panel's width until
    /// it has its place.
    room: Cell<f64>,
    /// How open the panel is, from 0 to 1, which its animation moves.
    openness: Cell<f64>,
    /// From the last placement: the messages' distance from the capsule's
    /// top, under the header bar, and the most the open panel may take.
    head: Cell<f64>,
    tallest: Cell<f64>,
}

pub struct Capsule {
    parts: Rc<Parts>,
    widening: adw::TimedAnimation,
    growth: adw::TimedAnimation,
    /// The overlay it floats in, which places it again when it moves.
    frame: gtk::Overlay,
}

impl Capsule {
    /// A capsule floating in `frame`, the overlay over the page's header
    /// bar `bar` and the page, where `start` is and never closer than
    /// [`CLEARANCE`] to `before`, with its surface under it.
    pub fn new(
        frame: &gtk::Overlay,
        start: &gtk::Widget,
        before: &gtk::Widget,
        bar: &gtk::Widget,
        post: Post,
    ) -> Self {
        let bell = gtk::Image::from_icon_name("egrio-bell-symbolic");
        bell.set_pixel_size(BELL);
        let count = gtk::Label::new(None);
        count.add_css_class("numeric");
        count.set_margin_start(GAP as i32);
        count.set_visible(false);
        let text = gtk::Label::new(None);
        text.add_css_class("egrio-capsule-text");
        text.set_ellipsize(gtk::pango::EllipsizeMode::End);
        text.set_single_line_mode(true);
        text.set_xalign(0.0);
        text.set_hexpand(true);
        text.set_margin_start(GAP as i32 + 2);
        text.set_margin_end(2);
        let content = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        content.append(&bell);
        content.append(&count);
        content.append(&text);
        let button = gtk::Button::new();
        button.set_widget_name("egrio-capsule");
        button.add_css_class("egrio-capsule");
        button.set_overflow(gtk::Overflow::Hidden);
        button.set_child(Some(&content));
        button.connect_clicked(move |_| post(UiEvent::Toolbar(ToolbarAction::Messages)));

        let surface = gtk::Box::new(gtk::Orientation::Vertical, 0);
        surface.set_widget_name("egrio-drawer");
        surface.add_css_class("egrio-drawer");
        let host = gtk::Box::new(gtk::Orientation::Vertical, 0);
        host.set_opacity(0.0);
        let scroller = gtk::ScrolledWindow::new();
        scroller.add_css_class("egrio-drawer-messages");
        // Neither direction follows the messages, so the scrolled window
        // takes any size and cuts them off; it shows no scroll bars.
        scroller.set_policy(gtk::PolicyType::External, gtk::PolicyType::External);
        scroller.set_child(Some(&host));
        // Under the capsule, which takes its clicks.
        frame.add_overlay(&surface);
        frame.add_overlay(&scroller);
        frame.add_overlay(&button);

        let parts = Rc::new(Parts {
            button,
            count,
            text,
            surface,
            scroller,
            host,
            shown: RefCell::new(None),
            width: Cell::new(0.0),
            target: Cell::new(0.0),
            room: Cell::new(WIDEST),
            openness: Cell::new(0.0),
            head: Cell::new(f64::from(HEIGHT)),
            tallest: Cell::new(DRAWER_HEIGHT),
        });
        let widening = {
            let (weak, frame) = (Rc::downgrade(&parts), frame.downgrade());
            let target = adw::CallbackAnimationTarget::new(move |width| {
                if let (Some(parts), Some(frame)) = (weak.upgrade(), frame.upgrade()) {
                    parts.width.set(width);
                    frame.queue_allocate();
                }
            });
            adw::TimedAnimation::new(&parts.button, 0.0, 0.0, DURATION, target)
        };
        widening.set_easing(adw::Easing::EaseOutCubic);
        let growth = {
            let (weak, frame) = (Rc::downgrade(&parts), frame.downgrade());
            let target = adw::CallbackAnimationTarget::new(move |openness| {
                if let (Some(parts), Some(frame)) = (weak.upgrade(), frame.upgrade()) {
                    parts.openness.set(openness);
                    parts.host.set_opacity(openness);
                    frame.queue_allocate();
                }
            });
            adw::TimedAnimation::new(&parts.surface, 0.0, 0.0, DURATION, target)
        };
        growth.set_easing(adw::Easing::EaseOutCubic);
        {
            // Open, the messages follow what they hold again.
            let weak = Rc::downgrade(&parts);
            growth.connect_done(move |growth| {
                if let Some(parts) = weak.upgrade() {
                    if growth.value_to() > 0.0 {
                        let (width, _) = parts.host.size_request();
                        parts.host.set_size_request(width, -1);
                    }
                }
            });
        }
        let this = Self {
            parts,
            widening,
            growth,
            frame: frame.clone(),
        };
        this.place(start, before, bar);
        this
    }

    pub fn button(&self) -> &gtk::Button {
        &self.parts.button
    }

    /// The capsule's surface, which is the open panel.
    pub fn panel(&self) -> &gtk::Box {
        &self.parts.surface
    }

    /// Where the panel's messages go.
    pub fn host(&self) -> &gtk::Box {
        &self.parts.host
    }

    /// Places the capsule where `start` is in the frame, centered on `bar`,
    /// as wide as it is now within the room before `before`, and its surface
    /// and messages under it, the messages below `bar`. A new room, as when the window changed
    /// size, fits the capsule at once; this runs while the overlay lays out,
    /// so it changes no widget but in an idle callback after.
    fn place(&self, start: &gtk::Widget, before: &gtk::Widget, bar: &gtk::Widget) {
        let (parts, widening) = (self.parts.clone(), self.widening.clone());
        let (start, before, bar) = (start.downgrade(), before.downgrade(), bar.downgrade());
        self.frame.connect_get_child_position(move |frame, child| {
            let bar = bar.upgrade()?.compute_bounds(frame)?;
            let capsule = capsule_place(
                &parts,
                &widening,
                frame,
                &start.upgrade()?,
                &before.upgrade()?,
                &bar,
            )?;
            if child == parts.button.upcast_ref::<gtk::Widget>() {
                return Some(capsule);
            }
            let is_surface = child == parts.surface.upcast_ref::<gtk::Widget>();
            if !is_surface && child != parts.scroller.upcast_ref::<gtk::Widget>() {
                return None;
            }
            parts
                .head
                .set(f64::from(bar.y() + bar.height()) - f64::from(capsule.y()) + BELOW_BAR);
            parts
                .tallest
                .set(DRAWER_HEIGHT.min(f64::from(frame.height() - capsule.y()) - MARGIN));
            let (surface, messages) = panel_places(&parts, capsule);
            child.measure(gtk::Orientation::Horizontal, -1);
            child.measure(gtk::Orientation::Vertical, -1);
            Some(if is_surface { surface } else { messages })
        });
    }

    /// Shows what the toolbar's message button says.
    pub fn update(&self, shown: &MessagesButton) {
        let toggled = match self.parts.shown.borrow().as_ref() {
            Some(old) if old == shown => return,
            Some(old) => old.open != shown.open,
            // The first view, which may have the panel open.
            None => shown.open,
        };
        *self.parts.shown.borrow_mut() = Some(shown.clone());
        show(&self.parts);
        retarget(&self.parts, &self.widening);
        if toggled {
            self.grow(shown.open);
        }
    }

    /// Opens the panel out of the capsule or closes it back into it; while
    /// it moves, its messages keep the open panel's size.
    fn grow(&self, open: bool) {
        let parts = &self.parts;
        let width = (open_width(parts) - 2.0 * INSET).max(1.0) as i32;
        if open {
            parts.host.set_size_request(width, -1);
            let natural = messages_height(&parts.host, width);
            let room = parts.tallest.get() - parts.head.get() - INSET;
            parts
                .host
                .set_size_request(width, f64::from(natural).min(room).max(0.0) as i32);
        } else {
            parts.host.set_size_request(width, parts.host.height());
        }
        for widget in [
            parts.surface.upcast_ref::<gtk::Widget>(),
            parts.button.upcast_ref(),
        ] {
            if open {
                widget.add_css_class(OPEN);
            } else {
                widget.remove_css_class(OPEN);
            }
        }
        parts.scroller.set_can_target(open);
        if !parts.surface.is_mapped() {
            self.growth.reset();
            parts.openness.set(if open { 1.0 } else { 0.0 });
            parts.host.set_opacity(parts.openness.get());
            self.frame.queue_allocate();
            return;
        }
        self.growth.set_value_from(parts.openness.get());
        self.growth.set_value_to(if open { 1.0 } else { 0.0 });
        self.growth.play();
    }
}

/// Where the capsule goes: where `start` is, centered on the header bar
/// `bar`, as wide as it is now within its room, which it takes in first.
fn capsule_place(
    parts: &Rc<Parts>,
    widening: &adw::TimedAnimation,
    frame: &gtk::Overlay,
    start: &gtk::Widget,
    before: &gtk::Widget,
    bar: &graphene::Rect,
) -> Option<gdk::Rectangle> {
    let start = start.compute_bounds(frame)?;
    let end = before.compute_bounds(frame)?;
    let x = f64::from(start.x());
    let room = f64::from(end.x()) - CLEARANCE - x;
    if (room - parts.room.get()).abs() >= 0.5 {
        parts.room.set(room);
        let width = target(parts);
        parts.target.set(width);
        if widening.state() == adw::AnimationState::Playing {
            widening.set_value_to(width);
        } else {
            parts.width.set(width);
        }
        // The open panel's messages take its new width, once the layout
        // that found it is done.
        let weak = Rc::downgrade(parts);
        glib::idle_add_local_once(move || {
            if let Some(parts) = weak.upgrade() {
                let (width, height) = parts.host.size_request();
                let open = (open_width(&parts) - 2.0 * INSET).max(1.0) as i32;
                if width != open {
                    parts.host.set_size_request(open, height);
                }
            }
        });
    }
    // Measured, as GTK asks before an allocation; the width is the
    // animation's, below the content's least while the text comes in,
    // which the capsule clips.
    parts.button.measure(gtk::Orientation::Horizontal, -1);
    parts.button.measure(gtk::Orientation::Vertical, -1);
    let width = parts.width.get().min(room).max(compact(parts));
    let y = bar.y() + (bar.height() - HEIGHT as f32) / 2.0;
    Some(gdk::Rectangle::new(
        x.round() as i32,
        y.round() as i32,
        width.round() as i32,
        HEIGHT,
    ))
}

/// How tall the messages stand at `width`, or at the least width they
/// take while they still keep an older one.
fn messages_height(host: &gtk::Box, width: i32) -> i32 {
    let (least, _, _, _) = host.measure(gtk::Orientation::Horizontal, -1);
    let (_, natural, _, _) = host.measure(gtk::Orientation::Vertical, width.max(least));
    natural
}

/// Where the panel's surface and its messages go under `capsule`: the
/// surface as wide as the capsule, from the capsule's height to its
/// messages' as it opens; the messages under the header bar, inset in it.
fn panel_places(parts: &Parts, capsule: gdk::Rectangle) -> (gdk::Rectangle, gdk::Rectangle) {
    let head = parts.head.get();
    let width = (open_width(parts) - 2.0 * INSET).max(1.0) as i32;
    let natural = messages_height(&parts.host, width);
    let closed = f64::from(HEIGHT);
    let open = (head + f64::from(natural) + INSET)
        .min(parts.tallest.get())
        .max(closed);
    let height = closed + (open - closed) * parts.openness.get();
    let surface = gdk::Rectangle::new(
        capsule.x(),
        capsule.y(),
        capsule.width(),
        height.round() as i32,
    );
    let messages = gdk::Rectangle::new(
        capsule.x() + INSET as i32,
        capsule.y() + head.round() as i32,
        (f64::from(capsule.width()) - 2.0 * INSET).max(0.0) as i32,
        (height - head - INSET).max(0.0).round() as i32,
    );
    (surface, messages)
}

/// Unread messages' tint while the panel is closed.
fn alert(shown: &MessagesButton) -> Option<&'static str> {
    if shown.open || shown.preview.is_none() {
        return None;
    }
    Some(match shown.level {
        Some(Level::Error) => "error",
        Some(Level::Warning) => "warning",
        Some(Level::Info) | None => "accent",
    })
}

/// A text's width in a label's font.
fn text_width(label: &gtk::Label, text: &str) -> f64 {
    f64::from(label.create_pango_layout(Some(text)).pixel_size().0)
}

/// The width of the bell and the count, with the ends.
fn compact(parts: &Parts) -> f64 {
    let count = parts
        .shown
        .borrow()
        .as_ref()
        .filter(|shown| shown.count > 0)
        .map_or(0.0, |shown| {
            GAP + text_width(&parts.count, &shown.count.to_string())
        });
    PADDING * 2.0 + f64::from(BELL) + count
}

/// The open panel's width: the widest the capsule gets in its room.
fn open_width(parts: &Parts) -> f64 {
    WIDEST.min(parts.room.get().max(compact(parts))).ceil()
}

/// The width the capsule heads for: the panel's while it is open, room for
/// the newest unread message while there is one, its bell and count
/// otherwise, within its room.
fn target(parts: &Parts) -> f64 {
    let Some(shown) = parts.shown.borrow().clone() else {
        return compact(parts).ceil();
    };
    let compact = compact(parts);
    let room = parts.room.get().max(compact);
    let width = match &shown.preview {
        _ if shown.open => return open_width(parts),
        Some(preview) if alert(&shown).is_some() => {
            (compact + GAP + 2.0 + text_width(&parts.text, &preview.text) + 2.0).min(room)
        }
        _ => compact,
    };
    width.ceil()
}

/// Gives the widgets what the capsule shows: its tint, count, text and help.
fn show(parts: &Parts) {
    let Some(shown) = parts.shown.borrow().clone() else {
        return;
    };
    let alert = alert(&shown);
    for tint in TINTS {
        if Some(tint) != alert {
            parts.button.remove_css_class(tint);
        }
    }
    if let Some(alert) = alert {
        parts.button.add_css_class(alert);
    }
    parts.count.set_visible(shown.count > 0);
    parts.count.set_text(&if shown.count > 0 {
        shown.count.to_string()
    } else {
        String::new()
    });
    // A cleared text keeps its words while it fades out.
    let preview = shown.preview.as_ref().filter(|_| alert.is_some());
    if let Some(preview) = preview {
        parts.text.set_text(&preview.text);
    }
    if preview.is_some() {
        parts.text.add_css_class("egrio-shown");
    } else {
        parts.text.remove_css_class("egrio-shown");
    }
    let help = preview.map_or(shown.label.as_str(), |preview| preview.help.as_str());
    parts.button.set_tooltip_text(Some(help));
    let mut name = vec![shown.label.clone()];
    if shown.count > 0 {
        name.push(shown.count.to_string());
    }
    name.extend(preview.map(|preview| preview.text.clone()));
    parts
        .button
        .update_property(&[gtk::accessible::Property::Label(&name.join(", "))]);
}

/// Heads the capsule for its new width: animated once it shows, at once
/// before.
fn retarget(parts: &Parts, widening: &adw::TimedAnimation) {
    let width = target(parts);
    if width == parts.target.get() {
        return;
    }
    parts.target.set(width);
    if parts.button.is_mapped() && parts.width.get() > 0.0 {
        widening.set_value_from(parts.width.get());
        widening.set_value_to(width);
        widening.play();
    } else {
        widening.reset();
        parts.width.set(width);
        if let Some(frame) = parts.button.parent() {
            frame.queue_allocate();
        }
    }
}
