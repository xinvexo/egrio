//! The message capsule at the start of the title bar's band over the page,
//! and the message panel that grows out of it. The capsule is always there:
//! a small surface with the bell and the number of messages, which keep one
//! size and place in every state, so nothing jumps. With unread messages it
//! stays expanded into the free space before the switches, tinted by the
//! most severe of them and showing the newest one cut to one line, until
//! they are read. A click opens or closes the panel. The capsule's surface is
//! the panel's: it lies over the window's content under the transparent
//! title bar, the capsule's bell, number and text drawn over it from the
//! title bar's view, so the panel grows out of the capsule and shrinks back
//! into it as one surface. It widens with the capsule and moves between the
//! capsule's height and its messages'; its tint gives way to the panel's
//! shadow and its messages fade in as it opens. All of it moves together
//! through `NSAnimationContext`, and only into the free space.

use std::cell::{Cell, OnceCell, RefCell};
use std::ptr::NonNull;

use block2::RcBlock;
use objc2::rc::{Retained, Weak};
use objc2::runtime::{AnyObject, NSObjectProtocol};
use objc2::{define_class, msg_send, AnyThread, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAccessibilityButtonRole, NSAccessibilityRole, NSAnimationContext, NSAppearance,
    NSAppearanceNameAqua, NSAppearanceNameDarkAqua, NSBox, NSBoxType, NSColor, NSEvent, NSFont,
    NSFontWeightMedium, NSImageView, NSLayoutConstraint, NSLineBreakMode, NSShadow, NSTextField,
    NSTitlePosition, NSTrackingArea, NSTrackingAreaOptions, NSView, NSVisualEffectBlendingMode,
    NSVisualEffectMaterial, NSVisualEffectState, NSVisualEffectView,
};
use objc2_foundation::{NSArray, NSRect, NSSize, NSString};
use objc2_quartz_core::{kCAMediaTimingFunctionEaseOut, CAMediaTimingFunction};

use egrio_ui::backend::{MessagesButton, ToolbarAction, UiEvent, DRAWER_HEIGHT, DRAWER_WIDTH};
use egrio_ui::messages::Level;

use super::style;

/// The capsule's height, which is also the open panel's head.
pub const HEIGHT: f64 = 26.0;
/// The capsule's ends and the gaps inside it.
const PADDING: f64 = 9.0;
const BELL: f64 = 15.0;
const GAP: f64 = 5.0;
/// The widest the capsule gets: the panel's width.
const WIDEST: f64 = DRAWER_WIDTH;
/// The least space left between the capsule and the switches.
const CLEARANCE: f64 = 16.0;
/// The capsule's tint over the panel's material, black over a light
/// appearance and white over a dark one, whose popover material is darker
/// than the window, and a little deeper under the pointer, as a button shows
/// it can be clicked; unread messages tint it with their color.
const TINT: Ink = Ink {
    light: 0.07,
    dark: 0.14,
};
const TINT_HOVERED: Ink = Ink {
    light: 0.11,
    dark: 0.2,
};
const ALERT: f64 = 0.14;
const ALERT_HOVERED: f64 = 0.2;
/// How long the capsule and its surface take to change; they ease out, so
/// they come to rest softly.
const DURATION: f64 = 0.25;

pub struct CapsuleIvars {
    bell: Retained<NSImageView>,
    count: Retained<NSTextField>,
    text: Retained<NSTextField>,
    /// The count's leading gap, zero without a count.
    count_gap: OnceCell<Retained<NSLayoutConstraint>>,
    width: OnceCell<Retained<NSLayoutConstraint>>,
    /// The capsule's surface, which is the panel's: the popover material,
    /// rounded like the capsule, cutting off the body while it grows.
    surface: Retained<NSVisualEffectView>,
    /// The surface's tints while it is the capsule, over the material and
    /// under the body: the plain one, and unread messages' color.
    tint: Retained<NSBox>,
    alert: Retained<NSBox>,
    /// Behind the surface: the open panel's shadow.
    shade: Retained<NSBox>,
    /// What the panel shows, as tall as its messages and as wide as the
    /// open panel, so the surface uncovers it as it grows and nothing in it
    /// wraps again on the way.
    body: Retained<NSView>,
    body_width: Retained<NSLayoutConstraint>,
    heights: OnceCell<Heights>,
    /// The surface's moves so far: a move's end settles the surface only if
    /// no later move started.
    moves: Cell<u64>,
    shown: RefCell<Option<MessagesButton>>,
    hovered: Cell<bool>,
    /// The first switch, which the capsule never grows into.
    trailing: RefCell<Option<Weak<NSView>>>,
    post: fn(UiEvent),
}

define_class!(
    /// The capsule; it takes every click inside it.
    #[unsafe(super(NSView))]
    #[name = "EgrioMessageCapsule"]
    #[thread_kind = MainThreadOnly]
    #[ivars = CapsuleIvars]
    pub struct MessageCapsule;

    unsafe impl NSObjectProtocol for MessageCapsule {}

    impl MessageCapsule {
        #[unsafe(method_id(hitTest:))]
        fn hit_test(&self, point: objc2_foundation::NSPoint) -> Option<Retained<NSView>> {
            let hit: Option<Retained<NSView>> = unsafe { msg_send![super(self), hitTest: point] };
            hit.map(|_| Retained::into_super(objc2::Message::retain(self)))
        }

        // The click is the capsule's: the title bar around it would take a
        // press it passes on as the start of dragging the window, and keep
        // the release.
        #[unsafe(method(mouseDown:))]
        fn mouse_down(&self, _event: &NSEvent) {}

        #[unsafe(method(mouseDownCanMoveWindow))]
        fn mouse_down_can_move_window(&self) -> bool {
            false
        }

        #[unsafe(method(acceptsFirstMouse:))]
        fn accepts_first_mouse(&self, _event: Option<&NSEvent>) -> bool {
            true
        }

        #[unsafe(method(mouseUp:))]
        fn mouse_up(&self, event: &NSEvent) {
            // Only a release over the capsule counts, as with a button.
            let point = self.convertPoint_fromView(event.locationInWindow(), None);
            if self.mouse_inRect(point, self.bounds()) {
                (self.ivars().post)(UiEvent::Toolbar(ToolbarAction::Messages));
            }
        }

        #[unsafe(method(mouseEntered:))]
        fn mouse_entered(&self, _event: &NSEvent) {
            self.ivars().hovered.set(true);
            self.paint();
        }

        #[unsafe(method(mouseExited:))]
        fn mouse_exited(&self, _event: &NSEvent) {
            self.ivars().hovered.set(false);
            self.paint();
        }

        #[unsafe(method(isAccessibilityElement))]
        fn is_accessibility_element(&self) -> bool {
            true
        }

        #[unsafe(method_id(accessibilityRole))]
        fn accessibility_role(&self) -> Option<Retained<NSAccessibilityRole>> {
            Some(objc2::Message::retain(unsafe { NSAccessibilityButtonRole }))
        }

        #[unsafe(method_id(accessibilityLabel))]
        fn accessibility_label(&self) -> Option<Retained<NSString>> {
            self.ivars().shown.borrow().as_ref().map(|shown| {
                let mut parts = vec![shown.label.clone()];
                if shown.count > 0 {
                    parts.push(shown.count.to_string());
                }
                parts.extend(shown.preview.as_ref().map(|preview| preview.text.clone()));
                NSString::from_str(&parts.join(", "))
            })
        }

        #[unsafe(method(accessibilityPerformPress))]
        fn accessibility_perform_press(&self) -> bool {
            (self.ivars().post)(UiEvent::Toolbar(ToolbarAction::Messages));
            true
        }
    }
);

/// What holds the surface's height: the capsule's while the panel is
/// closed, the body's while it is open, and a height of its own while it
/// moves between them. The move animates that height, so the window lays the
/// surface and everything in it out at each step.
struct Heights {
    collapsed: Retained<NSLayoutConstraint>,
    expanded: Retained<NSLayoutConstraint>,
    moving: Retained<NSLayoutConstraint>,
}

impl Heights {
    /// The constraint that holds the surface once it is open or closed.
    fn settled(&self, open: bool) -> &NSLayoutConstraint {
        if open {
            &self.expanded
        } else {
            &self.collapsed
        }
    }

    /// Lets `holding` alone hold the surface; the others let go first, so
    /// two never hold it at once.
    fn hold(&self, holding: &NSLayoutConstraint) {
        for constraint in [&self.collapsed, &self.expanded, &self.moving] {
            if !std::ptr::eq(&**constraint, holding) {
                constraint.setActive(false);
            }
        }
        holding.setActive(true);
    }
}

/// How strongly a tint covers a light appearance and a dark one.
#[derive(Clone, Copy)]
struct Ink {
    light: f64,
    dark: f64,
}

impl Ink {
    /// Black at the light strength over a light appearance, white at the
    /// dark one over a dark appearance, resolved wherever it is drawn.
    fn color(self) -> Retained<NSColor> {
        let provider = RcBlock::new(
            move |appearance: NonNull<NSAppearance>| -> NonNull<NSColor> {
                let names = unsafe {
                    NSArray::from_slice(&[NSAppearanceNameAqua, NSAppearanceNameDarkAqua])
                };
                let dark = unsafe { appearance.as_ref() }
                    .bestMatchFromAppearancesWithNames(&names)
                    .is_some_and(|name| unsafe { &*name == NSAppearanceNameDarkAqua });
                let color = if dark {
                    NSColor::colorWithWhite_alpha(1.0, self.dark)
                } else {
                    NSColor::colorWithWhite_alpha(0.0, self.light)
                };
                // Valid until the drawing that asked for it ends.
                NonNull::new(Retained::autorelease_ptr(color)).expect("a color")
            },
        );
        unsafe { NSColor::colorWithName_dynamicProvider(None, &provider) }
    }
}

/// A box filled with one color, rounded like the capsule.
fn rounded(mtm: MainThreadMarker) -> Retained<NSBox> {
    let rounded = NSBox::new(mtm);
    rounded.setBoxType(NSBoxType::Custom);
    rounded.setTitlePosition(NSTitlePosition::NoTitle);
    rounded.setCornerRadius(HEIGHT / 2.0);
    rounded.setBorderWidth(0.0);
    rounded.setFillColor(&NSColor::clearColor());
    rounded
}

impl MessageCapsule {
    pub fn new(mtm: MainThreadMarker, post: fn(UiEvent)) -> Retained<Self> {
        let bell = NSImageView::new(mtm);
        // A template the view tints, so its color follows the appearance.
        bell.setImage(style::sized_symbol("bell", 13.0).as_deref());
        bell.setTranslatesAutoresizingMaskIntoConstraints(false);
        let count = NSTextField::labelWithString(&NSString::from_str(""), mtm);
        count.setFont(Some(&style::numeric_font(12.0)));
        count.setTranslatesAutoresizingMaskIntoConstraints(false);
        let text = NSTextField::labelWithString(&NSString::from_str(""), mtm);
        text.setFont(Some(&*unsafe {
            NSFont::systemFontOfSize_weight(12.0, NSFontWeightMedium)
        }));
        text.setTextColor(Some(&NSColor::labelColor()));
        text.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
        text.setMaximumNumberOfLines(1);
        text.setTranslatesAutoresizingMaskIntoConstraints(false);
        text.setContentCompressionResistancePriority_forOrientation(
            250.0,
            objc2_app_kit::NSLayoutConstraintOrientation::Horizontal,
        );

        let surface = NSVisualEffectView::new(mtm);
        surface.setMaterial(NSVisualEffectMaterial::Popover);
        surface.setBlendingMode(NSVisualEffectBlendingMode::WithinWindow);
        surface.setState(NSVisualEffectState::Active);
        // Rounded through its mask image, as AppKit has visual effect views
        // shaped; the tints inside round themselves.
        surface.setMaskImage(Some(&style::rounded_mask(HEIGHT / 2.0)));
        surface.setClipsToBounds(true);
        surface.setTranslatesAutoresizingMaskIntoConstraints(false);
        let tint = rounded(mtm);
        let alert = rounded(mtm);
        super::widgets::pin(&tint, &surface, 0.0);
        super::widgets::pin(&alert, &surface, 0.0);
        let body = NSView::new(mtm);
        body.setTranslatesAutoresizingMaskIntoConstraints(false);
        surface.addSubview(&body);
        let body_width = body.widthAnchor().constraintEqualToConstant(WIDEST);
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
            body.topAnchor()
                .constraintEqualToAnchor(&surface.topAnchor()),
            body.leadingAnchor()
                .constraintEqualToAnchor(&surface.leadingAnchor()),
            body_width.clone(),
        ]));
        // The shade's own fill stays under the surface; only its shadow
        // shows, and only while the panel is open.
        let shade = rounded(mtm);
        shade.setFillColor(&NSColor::windowBackgroundColor());
        shade.setWantsLayer(true);
        let shadow = NSShadow::new();
        shadow.setShadowColor(Some(&NSColor::colorWithSRGBRed_green_blue_alpha(
            0.0, 0.0, 0.0, 0.18,
        )));
        shadow.setShadowBlurRadius(16.0);
        shadow.setShadowOffset(NSSize::new(0.0, -4.0));
        shade.setShadow(Some(&shadow));
        shade.setTranslatesAutoresizingMaskIntoConstraints(false);

        let this = Self::alloc(mtm).set_ivars(CapsuleIvars {
            bell: bell.clone(),
            count: count.clone(),
            text: text.clone(),
            count_gap: OnceCell::new(),
            width: OnceCell::new(),
            surface,
            tint,
            alert,
            shade,
            body,
            body_width,
            heights: OnceCell::new(),
            moves: Cell::new(0),
            shown: RefCell::new(None),
            hovered: Cell::new(false),
            trailing: RefCell::new(None),
            post,
        });
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        this.setTranslatesAutoresizingMaskIntoConstraints(false);
        for view in [bell.as_ref() as &NSView, count.as_ref(), text.as_ref()] {
            this.addSubview(view);
        }
        let width = this
            .widthAnchor()
            .constraintEqualToConstant(PADDING * 2.0 + BELL);
        let count_gap = count
            .leadingAnchor()
            .constraintEqualToAnchor_constant(&bell.trailingAnchor(), 0.0);
        let text_gap = text
            .leadingAnchor()
            .constraintEqualToAnchor_constant(&count.trailingAnchor(), GAP + 2.0);
        text_gap.setPriority(740.0);
        // The text ends inside the capsule, but never at the bell's cost: the
        // bare bell's capsule has no room for an empty count and text.
        let text_end = text
            .trailingAnchor()
            .constraintLessThanOrEqualToAnchor_constant(&this.trailingAnchor(), -PADDING - 2.0);
        text_end.setPriority(750.0);
        let _ = this.ivars().width.set(width.clone());
        let _ = this.ivars().count_gap.set(count_gap.clone());
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
            width,
            this.heightAnchor().constraintEqualToConstant(HEIGHT),
            // One bell, one size and place, whatever the capsule shows.
            bell.leadingAnchor()
                .constraintEqualToAnchor_constant(&this.leadingAnchor(), PADDING),
            bell.centerYAnchor()
                .constraintEqualToAnchor(&this.centerYAnchor()),
            bell.widthAnchor().constraintEqualToConstant(BELL),
            bell.heightAnchor().constraintEqualToConstant(BELL),
            count_gap,
            count
                .centerYAnchor()
                .constraintEqualToAnchor(&this.centerYAnchor()),
            // The text's gap gives way while there is no text, so the
            // capsule keeps its count.
            text.leadingAnchor()
                .constraintGreaterThanOrEqualToAnchor(&count.trailingAnchor()),
            text_gap,
            text_end,
            text.centerYAnchor()
                .constraintEqualToAnchor(&this.centerYAnchor()),
        ]));
        let area = unsafe {
            NSTrackingArea::initWithRect_options_owner_userInfo(
                NSTrackingArea::alloc(),
                NSRect::ZERO,
                NSTrackingAreaOptions::MouseEnteredAndExited
                    | NSTrackingAreaOptions::ActiveInActiveApp
                    | NSTrackingAreaOptions::InVisibleRect,
                Some(this.as_ref() as &AnyObject),
                None,
            )
        };
        this.addTrackingArea(&area);
        this
    }

    /// What the open panel shows, as tall as its messages.
    pub fn body(&self) -> &NSView {
        &self.ivars().body
    }

    /// The capsule's surface, which is the open panel.
    pub fn panel(&self) -> &NSView {
        &self.ivars().surface
    }

    /// Lays the capsule's surface over everything in `over`, under the
    /// capsule in the title bar: the same top, leading edge and width. The
    /// body is as tall as its messages, at most `DRAWER_HEIGHT` and no lower
    /// than `margin` above the bottom of `pane`, the page's.
    pub fn hang(&self, over: &NSView, pane: &NSView, margin: f64) {
        let ivars = self.ivars();
        let (surface, shade, body) = (&ivars.surface, &ivars.shade, &ivars.body);
        over.addSubview(shade);
        over.addSubview(surface);
        let heights = Heights {
            collapsed: surface
                .heightAnchor()
                .constraintEqualToAnchor(&self.heightAnchor()),
            expanded: surface
                .heightAnchor()
                .constraintEqualToAnchor(&body.heightAnchor()),
            moving: surface.heightAnchor().constraintEqualToConstant(HEIGHT),
        };
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
            surface
                .topAnchor()
                .constraintEqualToAnchor(&self.topAnchor()),
            surface
                .leadingAnchor()
                .constraintEqualToAnchor(&self.leadingAnchor()),
            surface
                .widthAnchor()
                .constraintEqualToAnchor(&self.widthAnchor()),
            shade
                .topAnchor()
                .constraintEqualToAnchor(&surface.topAnchor()),
            shade
                .leadingAnchor()
                .constraintEqualToAnchor(&surface.leadingAnchor()),
            shade
                .trailingAnchor()
                .constraintEqualToAnchor(&surface.trailingAnchor()),
            shade
                .bottomAnchor()
                .constraintEqualToAnchor(&surface.bottomAnchor()),
            body.heightAnchor()
                .constraintLessThanOrEqualToConstant(DRAWER_HEIGHT),
            body.bottomAnchor()
                .constraintLessThanOrEqualToAnchor_constant(&pane.bottomAnchor(), -margin),
        ]));
        let _ = ivars.heights.set(heights);
        self.refresh(false);
    }

    /// Keeps the capsule from growing into `trailing`, a view in the same
    /// window.
    pub fn keep_before(&self, trailing: &NSView) {
        *self.ivars().trailing.borrow_mut() = Some(Weak::from(trailing));
        self.fit();
    }

    /// Fits the capsule to the space it has, after the window changed size.
    pub fn fit(&self) {
        let ivars = self.ivars();
        let Some(shown) = ivars.shown.borrow().clone() else {
            return;
        };
        if let Some(width) = ivars.width.get() {
            width.setConstant(self.width_for(&shown));
        }
        ivars.body_width.setConstant(self.open_width(&shown));
    }

    pub fn update(&self, shown: &MessagesButton) {
        if self.ivars().shown.borrow().as_ref() == Some(shown) {
            return;
        }
        *self.ivars().shown.borrow_mut() = Some(shown.clone());
        self.refresh(true);
    }

    /// The widest the capsule can be before it comes near the switches;
    /// unbounded until they have their places.
    fn room(&self) -> f64 {
        let trailing = self.ivars().trailing.borrow();
        let Some(trailing) = trailing.as_ref().and_then(Weak::load) else {
            return WIDEST;
        };
        let start = self.convertRect_toView(self.bounds(), None).origin.x;
        let end = trailing
            .convertRect_toView(trailing.bounds(), None)
            .origin
            .x;
        if end <= start {
            return WIDEST;
        }
        (end - start - CLEARANCE).min(WIDEST)
    }

    /// Unread messages' color while the panel is closed.
    fn alert_color(shown: &MessagesButton) -> Option<Retained<NSColor>> {
        if shown.open || shown.preview.is_none() {
            return None;
        }
        Some(match shown.level {
            Some(Level::Error) => NSColor::systemRedColor(),
            Some(Level::Warning) => NSColor::systemOrangeColor(),
            Some(Level::Info) | None => NSColor::controlAccentColor(),
        })
    }

    /// The capsule with the bell and the count alone.
    fn compact_width(&self, shown: &MessagesButton) -> f64 {
        let count_width = if shown.count > 0 {
            GAP + self.ivars().count.intrinsicContentSize().width
        } else {
            0.0
        };
        PADDING * 2.0 + BELL + count_width
    }

    /// The open panel's width: the widest the capsule gets in the room it
    /// has.
    fn open_width(&self, shown: &MessagesButton) -> f64 {
        WIDEST
            .min(self.room().max(self.compact_width(shown)))
            .ceil()
    }

    /// The capsule's width for what it shows: the bell and the count, the
    /// newest unread message after them, or the panel's width while open.
    fn width_for(&self, shown: &MessagesButton) -> f64 {
        let compact = self.compact_width(shown);
        if shown.open {
            self.open_width(shown)
        } else if Self::alert_color(shown).is_some() {
            (compact + GAP + 2.0 + self.ivars().text.intrinsicContentSize().width + 2.0)
                .min(self.room().max(compact))
                .ceil()
        } else {
            compact.ceil()
        }
    }

    /// Colors the bell, the count and the tints; they change at once, as a
    /// button's surface does under the pointer.
    fn paint(&self) {
        let ivars = self.ivars();
        let Some(shown) = ivars.shown.borrow().clone() else {
            return;
        };
        let hovered = ivars.hovered.get() && !shown.open;
        let alert = Self::alert_color(&shown);
        let glyphs = alert.clone().unwrap_or_else(NSColor::secondaryLabelColor);
        ivars.bell.setContentTintColor(Some(&glyphs));
        ivars.count.setTextColor(Some(&glyphs));
        ivars
            .tint
            .setFillColor(&if hovered { TINT_HOVERED } else { TINT }.color());
        // A cleared alert keeps its color while it fades out.
        if let Some(alert) = alert {
            ivars
                .alert
                .setFillColor(&alert.colorWithAlphaComponent(if hovered {
                    ALERT_HOVERED
                } else {
                    ALERT
                }));
        }
    }

    /// Lays the capsule and its surface out for what they show, animating
    /// the change when `animate`.
    fn refresh(&self, animate: bool) {
        let ivars = self.ivars();
        let Some(shown) = ivars.shown.borrow().clone() else {
            return;
        };
        self.paint();
        let alert = Self::alert_color(&shown).is_some();
        ivars
            .count
            .setStringValue(&NSString::from_str(&if shown.count > 0 {
                shown.count.to_string()
            } else {
                String::new()
            }));
        if let Some(gap) = ivars.count_gap.get() {
            gap.setConstant(if shown.count > 0 { GAP } else { 0.0 });
        }
        let preview = shown.preview.as_ref().filter(|_| alert);
        // An emptied text keeps its old words while it fades out.
        if let Some(preview) = preview {
            ivars
                .text
                .setStringValue(&NSString::from_str(&preview.text));
        }
        super::hover_help::set(
            self,
            Some(preview.map_or(shown.label.as_str(), |preview| preview.help.as_str())),
        );
        let width = self.width_for(&shown);
        ivars.body_width.setConstant(self.open_width(&shown));
        let (Some(constraint), Some(heights)) = (ivars.width.get().cloned(), ivars.heights.get())
        else {
            if let Some(constraint) = ivars.width.get() {
                constraint.setConstant(width);
            }
            return;
        };
        let open = shown.open;
        let alphas = [
            (ivars.text.clone().into_super().into_super(), alert),
            (ivars.tint.clone().into_super(), !open && !alert),
            (ivars.alert.clone().into_super(), alert),
            (ivars.shade.clone().into_super(), open),
            (ivars.body.clone(), open),
        ];
        let window = self.window().filter(|_| animate);
        let Some(window) = window else {
            constraint.setConstant(width);
            heights.hold(heights.settled(open));
            for (view, shown) in &alphas {
                view.setAlphaValue(if *shown { 1.0 } else { 0.0 });
            }
            return;
        };
        // The surface moves from where it is, also from the middle of a move,
        // to the capsule's height or the body's, as the window has laid the
        // body out for what it shows now.
        let moving = (!heights.settled(open).isActive()).then(|| {
            window.layoutIfNeeded();
            let to = if open {
                ivars.body.frame().size.height
            } else {
                HEIGHT
            };
            heights
                .moving
                .setConstant(ivars.surface.frame().size.height);
            heights.hold(&heights.moving);
            ivars.moves.set(ivars.moves.get() + 1);
            (heights.moving.clone(), to)
        });
        let changes = RcBlock::new(move |context: NonNull<NSAnimationContext>| {
            let context = unsafe { context.as_ref() };
            context.setDuration(DURATION);
            context.setTimingFunction(Some(&CAMediaTimingFunction::functionWithName(unsafe {
                kCAMediaTimingFunctionEaseOut
            })));
            if constraint.constant() != width {
                let animator: Retained<NSLayoutConstraint> =
                    unsafe { msg_send![&*constraint, animator] };
                animator.setConstant(width);
            }
            if let Some((height, to)) = &moving {
                let animator: Retained<NSLayoutConstraint> =
                    unsafe { msg_send![&**height, animator] };
                animator.setConstant(*to);
            }
            for (view, shown) in &alphas {
                let animator: Retained<NSView> = unsafe { msg_send![&**view, animator] };
                animator.setAlphaValue(if *shown { 1.0 } else { 0.0 });
            }
        });
        let this = objc2::Message::retain(self);
        let move_number = ivars.moves.get();
        let done = RcBlock::new(move || {
            let ivars = this.ivars();
            if let Some(heights) = ivars.heights.get() {
                if ivars.moves.get() == move_number && heights.moving.isActive() {
                    heights.hold(heights.settled(open));
                }
            }
        });
        NSAnimationContext::runAnimationGroup_completionHandler(&changes, Some(&done));
    }
}
