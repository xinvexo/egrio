//! The tile grid as an `NSCollectionView` with a grid layout: as many tiles
//! to a row as fit at their least width, stretched to share the row. The
//! collection view asks for the tiles it shows and reuses their views as it
//! scrolls, so a few thousand tiles cost only the visible ones; a changed
//! tile that has a view takes its new content in place. A tile is drawn
//! like a card and acts as a button: it lights up under the pointer and
//! while pressed, and reports a press released inside it. The selected
//! tile has the accent edge, and a check mark after its title where the
//! grid checks its selection. A testable
//! tile's value is a button of its own at the end of its second line, the
//! test symbol before its first result, which lights up and reports a test
//! instead of a press.

use std::cell::{Cell as StdCell, RefCell};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObjectProtocol, ProtocolObject};
use objc2::{
    define_class, msg_send, AnyThread, ClassType, DeclaredClass, MainThreadMarker, MainThreadOnly,
    Message,
};
use objc2_app_kit::{
    NSAccessibility, NSAccessibilityButtonRole, NSAccessibilityRole, NSBox, NSCollectionView,
    NSCollectionViewDataSource, NSCollectionViewGridLayout, NSCollectionViewItem,
    NSCollectionViewLayout, NSColor, NSControlSize, NSEvent, NSFont, NSFontWeightMedium,
    NSImageView, NSIndexPathNSCollectionViewAdditions, NSLayoutConstraint,
    NSLayoutConstraintOrientation, NSLineBreakMode, NSProgressIndicator, NSProgressIndicatorStyle,
    NSScrollView, NSTextField, NSTrackingArea, NSTrackingAreaOptions, NSView,
};
use objc2_foundation::{
    NSArray, NSEdgeInsets, NSIndexPath, NSInteger, NSObject, NSPoint, NSRect, NSSize, NSString,
};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{Icon, KeyedChanges, TextStyle, Tile, TileValue, Tiles};
use egrio_ui::reconcile::NodeId;

use super::style;
use super::widgets::{self, TEXT_COMPRESSION};

const TILE: &str = "tile";
/// Space between tiles, across and down.
const SPACING: f64 = 10.0;
/// Space inside a tile's edges.
const INSET: f64 = 14.0;
const MARK: f64 = 11.0;
const CHECK: f64 = 12.0;
const HOVER_ALPHA: f64 = 0.035;
const PRESS_ALPHA: f64 = 0.08;
/// Space around the test button's content, which its highlight covers.
const TEST_PADDING: f64 = 4.0;

/// Who a tile reports its press and test to.
#[derive(Clone, Copy)]
struct Owner {
    id: NodeId,
    post: fn(UiEvent),
}

#[derive(Default)]
struct TileState {
    key: String,
    title: String,
    tooltip: Option<String>,
    pressable: bool,
    selected: bool,
    testable: bool,
    owner: Option<Owner>,
    hovered: bool,
    /// The pointer is over the test button, which lights up instead.
    over_test: bool,
    /// The mouse went down on the tile and has not come up.
    tracking: bool,
    /// While tracking, whether the mouse is inside.
    inside: bool,
}

impl TileState {
    fn post(&self, event: impl FnOnce(String) -> Event) {
        if let Some(owner) = self.owner {
            (owner.post)(UiEvent::Node {
                id: owner.id,
                event: event(self.key.clone()),
            });
        }
    }
}

pub struct TileIvars {
    surface: Retained<NSBox>,
    highlight: Retained<NSBox>,
    title: Retained<NSTextField>,
    check: Retained<NSImageView>,
    /// The check mark's width and the gap before it, zero unless selected.
    check_width: Retained<NSLayoutConstraint>,
    check_gap: Retained<NSLayoutConstraint>,
    kind: Retained<NSTextField>,
    detail: Retained<NSTextField>,
    mark: Retained<NSImageView>,
    /// The mark's width and the gap before it, zero without a mark.
    mark_width: Retained<NSLayoutConstraint>,
    mark_gap: Retained<NSLayoutConstraint>,
    test: Retained<TestButton>,
    state: RefCell<TileState>,
    /// Whether the title is cut, which puts it in the tooltip.
    cut: StdCell<bool>,
}

define_class!(
    /// One tile: a card with its title over a line of kind, detail, mark
    /// and value. It takes every click inside it but on its test button, so
    /// its labels never do.
    #[unsafe(super(NSView))]
    #[name = "EgrioTileView"]
    #[thread_kind = MainThreadOnly]
    #[ivars = TileIvars]
    pub struct TileView;

    unsafe impl NSObjectProtocol for TileView {}

    impl TileView {
        #[unsafe(method_id(hitTest:))]
        fn hit_test(&self, point: NSPoint) -> Option<Retained<NSView>> {
            let hit: Option<Retained<NSView>> = unsafe { msg_send![super(self), hitTest: point] };
            let test = &self.ivars().test;
            let on_test = hit
                .as_ref()
                .is_some_and(|hit| hit.isDescendantOf(test.as_ref()));
            if on_test && self.ivars().state.borrow().testable {
                Some(Retained::into_super(test.retain()))
            } else {
                hit.map(|_| Retained::into_super(self.retain()))
            }
        }

        #[unsafe(method(mouseDown:))]
        fn mouse_down(&self, _event: &NSEvent) {
            let mut state = self.ivars().state.borrow_mut();
            if state.pressable {
                state.tracking = true;
                state.inside = true;
            }
            drop(state);
            self.refresh_highlight();
        }

        #[unsafe(method(mouseDragged:))]
        fn mouse_dragged(&self, event: &NSEvent) {
            let inside = contains(self, event);
            let mut state = self.ivars().state.borrow_mut();
            if state.tracking && state.inside != inside {
                state.inside = inside;
                drop(state);
                self.refresh_highlight();
            }
        }

        #[unsafe(method(mouseUp:))]
        fn mouse_up(&self, event: &NSEvent) {
            let inside = contains(self, event);
            let mut state = self.ivars().state.borrow_mut();
            let pressed = state.tracking && inside && state.pressable;
            state.tracking = false;
            state.inside = false;
            drop(state);
            self.refresh_highlight();
            if pressed {
                self.ivars().state.borrow().post(Event::TilePressed);
            }
        }

        #[unsafe(method(mouseEntered:))]
        fn mouse_entered(&self, _event: &NSEvent) {
            self.ivars().state.borrow_mut().hovered = true;
            self.refresh_highlight();
        }

        #[unsafe(method(mouseExited:))]
        fn mouse_exited(&self, _event: &NSEvent) {
            self.ivars().state.borrow_mut().hovered = false;
            self.refresh_highlight();
        }

        #[unsafe(method(layout))]
        fn layout(&self) {
            let _: () = unsafe { msg_send![super(self), layout] };
            let title = &self.ivars().title;
            let cut = title.intrinsicContentSize().width > title.frame().size.width + 0.5;
            if cut != self.ivars().cut.replace(cut) {
                self.refresh_tooltip();
            }
        }

        #[unsafe(method(isAccessibilityElement))]
        fn is_accessibility_element(&self) -> bool {
            true
        }

        #[unsafe(method_id(accessibilityRole))]
        fn accessibility_role(&self) -> Option<Retained<NSAccessibilityRole>> {
            Some(unsafe { NSAccessibilityButtonRole }.retain())
        }

        #[unsafe(method(isAccessibilityEnabled))]
        fn is_accessibility_enabled(&self) -> bool {
            self.ivars().state.borrow().pressable
        }

        #[unsafe(method(isAccessibilitySelected))]
        fn is_accessibility_selected(&self) -> bool {
            self.ivars().state.borrow().selected
        }

        #[unsafe(method_id(accessibilityLabel))]
        fn accessibility_label(&self) -> Option<Retained<NSString>> {
            let ivars = self.ivars();
            let parts: Vec<String> = [&ivars.title, &ivars.kind, &ivars.detail]
                .into_iter()
                .chain(std::iter::once(&ivars.test.ivars().value))
                .filter(|field| !field.isHidden())
                .map(|field| field.stringValue().to_string())
                .filter(|text| !text.is_empty())
                .collect();
            Some(NSString::from_str(&parts.join(", ")))
        }

        #[unsafe(method(accessibilityPerformPress))]
        fn accessibility_perform_press(&self) -> bool {
            let state = self.ivars().state.borrow();
            if state.pressable {
                state.post(Event::TilePressed);
            }
            state.pressable
        }
    }
);

pub struct TestIvars {
    highlight: Retained<NSBox>,
    value: Retained<NSTextField>,
    symbol: Retained<NSImageView>,
    spinner: Retained<NSProgressIndicator>,
    /// The mouse went down on the button and has not come up; while it is
    /// down, whether it is inside.
    tracking: StdCell<bool>,
    inside: StdCell<bool>,
}

define_class!(
    /// A tile's test button: its value, or the test symbol before the
    /// first result, at the end of the tile's second line.
    #[unsafe(super(NSView))]
    #[name = "EgrioTileTestButton"]
    #[thread_kind = MainThreadOnly]
    #[ivars = TestIvars]
    pub struct TestButton;

    unsafe impl NSObjectProtocol for TestButton {}

    impl TestButton {
        #[unsafe(method(mouseDown:))]
        fn mouse_down(&self, _event: &NSEvent) {
            self.ivars().tracking.set(true);
            self.ivars().inside.set(true);
            self.refresh();
        }

        #[unsafe(method(mouseDragged:))]
        fn mouse_dragged(&self, event: &NSEvent) {
            if self.ivars().tracking.get() {
                self.ivars().inside.set(contains(self, event));
                self.refresh();
            }
        }

        #[unsafe(method(mouseUp:))]
        fn mouse_up(&self, event: &NSEvent) {
            let pressed = self.ivars().tracking.replace(false) && contains(self, event);
            self.ivars().inside.set(false);
            self.refresh();
            if let (true, Some(tile)) = (pressed, self.tile()) {
                let state = tile.ivars().state.borrow();
                if state.testable {
                    state.post(Event::TileTested);
                }
            }
        }

        #[unsafe(method(mouseEntered:))]
        fn mouse_entered(&self, _event: &NSEvent) {
            if let Some(tile) = self.tile() {
                tile.ivars().state.borrow_mut().over_test = true;
                tile.refresh_highlight();
            }
            self.refresh();
        }

        #[unsafe(method(mouseExited:))]
        fn mouse_exited(&self, _event: &NSEvent) {
            if let Some(tile) = self.tile() {
                tile.ivars().state.borrow_mut().over_test = false;
                tile.refresh_highlight();
            }
            self.refresh();
        }

        #[unsafe(method(isAccessibilityElement))]
        fn is_accessibility_element(&self) -> bool {
            self.tile()
                .is_some_and(|tile| tile.ivars().state.borrow().testable)
        }

        #[unsafe(method_id(accessibilityRole))]
        fn accessibility_role(&self) -> Option<Retained<NSAccessibilityRole>> {
            Some(unsafe { NSAccessibilityButtonRole }.retain())
        }

        #[unsafe(method(accessibilityPerformPress))]
        fn accessibility_perform_press(&self) -> bool {
            self.tile().is_some_and(|tile| {
                let state = tile.ivars().state.borrow();
                if state.testable {
                    state.post(Event::TileTested);
                }
                state.testable
            })
        }
    }
);

impl TestButton {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let value = label(
            mtm,
            &*unsafe { NSFont::monospacedDigitSystemFontOfSize_weight(11.0, NSFontWeightMedium) },
            &NSColor::secondaryLabelColor(),
        );
        priorities(&value, 750.0, 760.0);
        let symbol = NSImageView::new(mtm);
        symbol.setContentTintColor(Some(&NSColor::secondaryLabelColor()));
        symbol.setAccessibilityElement(false);
        symbol.setTranslatesAutoresizingMaskIntoConstraints(false);
        let spinner = NSProgressIndicator::new(mtm);
        spinner.setStyle(NSProgressIndicatorStyle::Spinning);
        spinner.setControlSize(NSControlSize::Mini);
        spinner.setIndeterminate(true);
        spinner.setDisplayedWhenStopped(false);
        spinner.setTranslatesAutoresizingMaskIntoConstraints(false);
        let highlight = NSBox::new(mtm);
        highlight.setBoxType(objc2_app_kit::NSBoxType::Custom);
        highlight.setTitlePosition(objc2_app_kit::NSTitlePosition::NoTitle);
        highlight.setCornerRadius(5.0);
        highlight.setBorderWidth(0.0);
        highlight.setHidden(true);
        let this = Self::alloc(mtm).set_ivars(TestIvars {
            highlight: highlight.clone(),
            value: value.clone(),
            symbol: symbol.clone(),
            spinner: spinner.clone(),
            tracking: StdCell::new(false),
            inside: StdCell::new(false),
        });
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        this.setTranslatesAutoresizingMaskIntoConstraints(false);
        widgets::pin(&highlight, &this, 0.0);
        for view in [value.as_ref(), symbol.as_ref(), spinner.as_ref() as &NSView] {
            this.addSubview(view);
        }
        let mut constraints = Vec::new();
        for view in [value.as_ref() as &NSView, symbol.as_ref(), spinner.as_ref()] {
            constraints.push(
                view.trailingAnchor()
                    .constraintEqualToAnchor_constant(&this.trailingAnchor(), -TEST_PADDING),
            );
            constraints.push(
                view.centerYAnchor()
                    .constraintEqualToAnchor(&this.centerYAnchor()),
            );
            // As wide as what it shows, whichever of them that is.
            constraints.push(
                this.leadingAnchor()
                    .constraintLessThanOrEqualToAnchor_constant(
                        &view.leadingAnchor(),
                        -TEST_PADDING,
                    ),
            );
        }
        let tight = this.widthAnchor().constraintEqualToConstant(0.0);
        tight.setPriority(250.0);
        constraints.push(tight);
        constraints.push(this.heightAnchor().constraintEqualToConstant(20.0));
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&constraints));
        let area = unsafe {
            NSTrackingArea::initWithRect_options_owner_userInfo(
                NSTrackingArea::alloc(),
                NSRect::ZERO,
                NSTrackingAreaOptions::MouseEnteredAndExited
                    | NSTrackingAreaOptions::ActiveInKeyWindow
                    | NSTrackingAreaOptions::InVisibleRect,
                Some(this.as_ref() as &AnyObject),
                None,
            )
        };
        this.addTrackingArea(&area);
        this
    }

    fn tile(&self) -> Option<Retained<TileView>> {
        // The button is the tile's own subview.
        unsafe { self.superview() }.and_then(|view| view.downcast::<TileView>().ok())
    }

    /// Lights up under the pointer and while pressed, when it can test.
    fn refresh(&self) {
        let ivars = self.ivars();
        let state = self.tile().map(|tile| {
            let state = tile.ivars().state.borrow();
            (state.testable, state.over_test)
        });
        let (testable, hovered) = state.unwrap_or((false, false));
        let alpha = if !testable {
            None
        } else if ivars.tracking.get() && ivars.inside.get() {
            Some(PRESS_ALPHA * 1.5)
        } else if hovered {
            Some(HOVER_ALPHA * 2.0)
        } else {
            None
        };
        match alpha {
            Some(alpha) => {
                ivars
                    .highlight
                    .setFillColor(&NSColor::labelColor().colorWithAlphaComponent(alpha));
                ivars.highlight.setHidden(false);
            }
            None => ivars.highlight.setHidden(true),
        }
    }

    /// Shows the tile's value, or the test symbol for an untested tile that
    /// can be tested.
    fn show(&self, value: &TileValue, testable: bool, label: &str) {
        let ivars = self.ivars();
        let text = |shown: Option<(&str, &Retained<NSColor>)>| match shown {
            Some((text, color)) => {
                ivars.value.setStringValue(&NSString::from_str(text));
                ivars.value.setTextColor(Some(color));
                ivars.value.setHidden(false);
            }
            None => {
                ivars.value.setStringValue(&NSString::from_str(""));
                ivars.value.setHidden(true);
            }
        };
        match value {
            TileValue::None => text(None),
            TileValue::Text { text: value, tone } => text(Some((value, &style::color(*tone)))),
            TileValue::Progress => text(None),
        }
        match value {
            TileValue::Progress => unsafe { ivars.spinner.startAnimation(None) },
            _ => unsafe { ivars.spinner.stopAnimation(None) },
        }
        let symbol = testable && *value == TileValue::None;
        ivars.symbol.setImage(
            if symbol {
                style::symbol(Icon::Zap)
            } else {
                None
            }
            .as_deref(),
        );
        ivars.symbol.setHidden(!symbol);
        super::hover_help::set(self, testable.then_some(label));
        self.setAccessibilityLabel(Some(&NSString::from_str(label)));
        self.refresh();
    }
}

fn contains(view: &NSView, event: &NSEvent) -> bool {
    let point = view.convertPoint_fromView(event.locationInWindow(), None);
    view.mouse_inRect(point, view.bounds())
}

fn label(mtm: MainThreadMarker, font: &NSFont, color: &NSColor) -> Retained<NSTextField> {
    let field = NSTextField::labelWithString(&NSString::from_str(""), mtm);
    field.setFont(Some(font));
    field.setTextColor(Some(color));
    field.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
    field.setMaximumNumberOfLines(1);
    field.setAccessibilityElement(false);
    field.setTranslatesAutoresizingMaskIntoConstraints(false);
    field
}

fn priorities(view: &NSView, hugging: f32, compression: f32) {
    view.setContentHuggingPriority_forOrientation(
        hugging,
        NSLayoutConstraintOrientation::Horizontal,
    );
    view.setContentCompressionResistancePriority_forOrientation(
        compression,
        NSLayoutConstraintOrientation::Horizontal,
    );
}

impl TileView {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let secondary = style::font(TextStyle::Caption);
        let title = label(
            mtm,
            &*unsafe { NSFont::systemFontOfSize_weight(13.0, NSFontWeightMedium) },
            &NSColor::labelColor(),
        );
        let kind = label(mtm, &secondary, &NSColor::secondaryLabelColor());
        let detail = label(mtm, &secondary, &NSColor::tertiaryLabelColor());
        priorities(&title, 250.0, TEXT_COMPRESSION);
        priorities(&kind, 750.0, 750.0);
        // The detail gives way first when the line is too narrow.
        priorities(&detail, 750.0, 250.0);
        let mark = NSImageView::new(mtm);
        mark.setImage(style::symbol(Icon::Link).as_deref());
        mark.setContentTintColor(Some(&NSColor::tertiaryLabelColor()));
        mark.setAccessibilityElement(false);
        mark.setTranslatesAutoresizingMaskIntoConstraints(false);
        let check = NSImageView::new(mtm);
        check.setImage(style::symbol(Icon::Check).as_deref());
        check.setContentTintColor(Some(&NSColor::controlAccentColor()));
        check.setAccessibilityElement(false);
        check.setTranslatesAutoresizingMaskIntoConstraints(false);
        let test = TestButton::new(mtm);

        let surface = widgets::card_box(mtm);
        let highlight = NSBox::new(mtm);
        highlight.setBoxType(objc2_app_kit::NSBoxType::Custom);
        highlight.setTitlePosition(objc2_app_kit::NSTitlePosition::NoTitle);
        highlight.setCornerRadius(10.0);
        highlight.setBorderWidth(0.0);
        highlight.setHidden(true);

        let this = Self::alloc(mtm).set_ivars(TileIvars {
            surface: surface.clone(),
            highlight: highlight.clone(),
            title: title.clone(),
            check: check.clone(),
            check_width: check.widthAnchor().constraintEqualToConstant(0.0),
            check_gap: check
                .leadingAnchor()
                .constraintEqualToAnchor_constant(&title.trailingAnchor(), 0.0),
            kind: kind.clone(),
            detail: detail.clone(),
            mark: mark.clone(),
            mark_gap: mark
                .leadingAnchor()
                .constraintEqualToAnchor_constant(&detail.trailingAnchor(), 0.0),
            mark_width: mark.widthAnchor().constraintEqualToConstant(0.0),
            test: test.clone(),
            state: RefCell::new(TileState::default()),
            cut: StdCell::new(false),
        });
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        for view in [&*surface, &*highlight] {
            widgets::pin(view, &this, 0.0);
        }
        for view in [
            title.as_ref() as &NSView,
            check.as_ref(),
            kind.as_ref(),
            detail.as_ref(),
            mark.as_ref(),
            test.as_ref(),
        ] {
            this.addSubview(view);
        }
        let ivars = this.ivars();
        NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
            title
                .leadingAnchor()
                .constraintEqualToAnchor_constant(&this.leadingAnchor(), INSET),
            title
                .bottomAnchor()
                .constraintEqualToAnchor_constant(&this.centerYAnchor(), 0.0),
            ivars.check_gap.clone(),
            ivars.check_width.clone(),
            check
                .trailingAnchor()
                .constraintEqualToAnchor_constant(&this.trailingAnchor(), -INSET),
            check.heightAnchor().constraintEqualToConstant(CHECK),
            check
                .centerYAnchor()
                .constraintEqualToAnchor(&title.centerYAnchor()),
            kind.leadingAnchor()
                .constraintEqualToAnchor_constant(&this.leadingAnchor(), INSET),
            kind.topAnchor()
                .constraintEqualToAnchor_constant(&this.centerYAnchor(), 2.0),
            detail
                .leadingAnchor()
                .constraintEqualToAnchor_constant(&kind.trailingAnchor(), 4.0),
            detail
                .firstBaselineAnchor()
                .constraintEqualToAnchor(&kind.firstBaselineAnchor()),
            ivars.mark_gap.clone(),
            ivars.mark_width.clone(),
            mark.heightAnchor().constraintEqualToConstant(MARK),
            mark.centerYAnchor()
                .constraintEqualToAnchor(&kind.centerYAnchor()),
            test.leadingAnchor()
                .constraintGreaterThanOrEqualToAnchor_constant(&mark.trailingAnchor(), 4.0),
            // The value lines up with the title's end, its padding beyond it.
            test.trailingAnchor()
                .constraintEqualToAnchor_constant(&this.trailingAnchor(), -INSET + TEST_PADDING),
            test.centerYAnchor()
                .constraintEqualToAnchor(&kind.centerYAnchor()),
        ]));
        let area = unsafe {
            NSTrackingArea::initWithRect_options_owner_userInfo(
                NSTrackingArea::alloc(),
                NSRect::ZERO,
                NSTrackingAreaOptions::MouseEnteredAndExited
                    | NSTrackingAreaOptions::ActiveInKeyWindow
                    | NSTrackingAreaOptions::InVisibleRect,
                Some(this.as_ref() as &AnyObject),
                None,
            )
        };
        this.addTrackingArea(&area);
        this
    }

    fn refresh_highlight(&self) {
        let state = self.ivars().state.borrow();
        let alpha = if state.tracking && state.inside {
            Some(PRESS_ALPHA)
        } else if state.hovered && state.pressable && !(state.over_test && state.testable) {
            Some(HOVER_ALPHA)
        } else {
            None
        };
        let highlight = &self.ivars().highlight;
        match alpha {
            Some(alpha) => {
                highlight.setFillColor(&NSColor::labelColor().colorWithAlphaComponent(alpha));
                highlight.setHidden(false);
            }
            None => highlight.setHidden(true),
        }
    }

    /// The tile's tooltip, led by its title while the title is cut.
    fn refresh_tooltip(&self) {
        let state = self.ivars().state.borrow();
        let lines: Vec<&str> = self
            .ivars()
            .cut
            .get()
            .then_some(state.title.as_str())
            .into_iter()
            .chain(state.tooltip.as_deref())
            .collect();
        let tooltip = (!lines.is_empty()).then(|| lines.join("\n"));
        super::hover_help::set(self, tooltip.as_deref());
    }

    /// Shows `tile`, reporting its press and test to `owner`, with the
    /// grid's way of marking its selection and naming its test button.
    fn show(&self, tile: &Tile, owner: Owner, grid: &Tiles) {
        let ivars = self.ivars();
        {
            let mut state = ivars.state.borrow_mut();
            if state.key != tile.key {
                state.tracking = false;
            }
            state.key = tile.key.clone();
            state.title = tile.title.clone();
            state.tooltip = tile.tooltip.clone();
            state.pressable = tile.pressable;
            state.selected = tile.selected;
            state.testable = tile.testable;
            state.owner = Some(owner);
        }
        ivars.title.setStringValue(&NSString::from_str(&tile.title));
        ivars.kind.setStringValue(&NSString::from_str(&tile.kind));
        ivars.detail.setStringValue(&NSString::from_str(
            &tile
                .detail
                .as_deref()
                .map(|detail| format!("· {detail}"))
                .unwrap_or_default(),
        ));
        let marked = tile.mark.is_some();
        if let Some(icon) = tile.mark {
            ivars.mark.setImage(style::symbol(icon).as_deref());
        }
        ivars.mark.setHidden(!marked);
        ivars
            .mark_width
            .setConstant(if marked { MARK } else { 0.0 });
        ivars.mark_gap.setConstant(if marked { 3.0 } else { 0.0 });
        let checked = tile.selected && grid.check;
        ivars.check.setHidden(!checked);
        ivars
            .check_width
            .setConstant(if checked { CHECK } else { 0.0 });
        ivars.check_gap.setConstant(if checked { 6.0 } else { 0.0 });
        // The one in use has the accent edge.
        if tile.selected {
            ivars.surface.setBorderColor(&NSColor::controlAccentColor());
            ivars.surface.setBorderWidth(2.0);
        } else {
            ivars.surface.setBorderColor(&NSColor::separatorColor());
            ivars.surface.setBorderWidth(1.0);
        }
        ivars
            .test
            .show(&tile.value, tile.testable, &grid.test_label);
        self.setAlphaValue(if tile.dimmed { 0.55 } else { 1.0 });
        self.refresh_highlight();
        self.refresh_tooltip();
    }
}

define_class!(
    /// The item the collection view makes and reuses for each tile; its view
    /// is a tile view, made in code.
    #[unsafe(super(NSCollectionViewItem))]
    #[name = "EgrioTileItem"]
    #[thread_kind = MainThreadOnly]
    pub struct TileItem;

    unsafe impl NSObjectProtocol for TileItem {}

    impl TileItem {
        #[unsafe(method(loadView))]
        fn load_view(&self) {
            self.setView(&TileView::new(MainThreadMarker::from(self)));
        }
    }
);

struct Data {
    owner: Owner,
    tiles: Tiles,
}

pub struct SourceIvars {
    data: RefCell<Data>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioTilesSource"]
    #[thread_kind = MainThreadOnly]
    #[ivars = SourceIvars]
    pub struct TilesSource;

    unsafe impl NSObjectProtocol for TilesSource {}

    unsafe impl NSCollectionViewDataSource for TilesSource {
        #[unsafe(method(collectionView:numberOfItemsInSection:))]
        fn number_of_items(&self, _view: &NSCollectionView, _section: NSInteger) -> NSInteger {
            self.ivars().data.borrow().tiles.tiles.len() as NSInteger
        }

        #[unsafe(method_id(collectionView:itemForRepresentedObjectAtIndexPath:))]
        fn item_for(
            &self,
            view: &NSCollectionView,
            path: &NSIndexPath,
        ) -> Retained<NSCollectionViewItem> {
            let item = view.makeItemWithIdentifier_forIndexPath(&NSString::from_str(TILE), path);
            let data = self.ivars().data.borrow();
            let tile = usize::try_from(path.item())
                .ok()
                .and_then(|index| data.tiles.tiles.get(index));
            if let (Some(tile), Ok(tile_view)) = (tile, item.view().downcast::<TileView>()) {
                tile_view.show(tile, data.owner, &data.tiles);
            }
            item
        }
    }
);

pub struct TilesHost {
    container: Retained<NSView>,
    collection: Retained<NSCollectionView>,
    layout: Retained<NSCollectionViewGridLayout>,
    source: Retained<TilesSource>,
    empty: Retained<NSTextField>,
}

impl TilesHost {
    pub fn new(mtm: MainThreadMarker, id: NodeId, props: &Tiles, post: fn(UiEvent)) -> Self {
        let source = TilesSource::alloc(mtm).set_ivars(SourceIvars {
            data: RefCell::new(Data {
                owner: Owner { id, post },
                tiles: props.clone(),
            }),
        });
        let source: Retained<TilesSource> = unsafe { msg_send![super(source), init] };
        let clear = NSArray::from_retained_slice(&[NSColor::clearColor()]);
        let layout = NSCollectionViewGridLayout::new(mtm);
        layout.setMinimumInteritemSpacing(SPACING);
        layout.setMinimumLineSpacing(SPACING);
        layout.setMargins(NSEdgeInsets {
            top: 0.0,
            left: 0.0,
            bottom: 0.0,
            right: 0.0,
        });
        layout.setBackgroundColors(Some(&clear));
        let collection = NSCollectionView::new(mtm);
        let base: &NSCollectionViewLayout = &layout;
        collection.setCollectionViewLayout(Some(base));
        collection.setBackgroundColors(Some(&clear));
        collection.setSelectable(false);
        unsafe {
            collection.registerClass_forItemWithIdentifier(
                Some(TileItem::class()),
                &NSString::from_str(TILE),
            );
        }
        collection.setDataSource(Some(ProtocolObject::from_ref(&*source)));
        let scroll = NSScrollView::new(mtm);
        scroll.setDocumentView(Some(&collection));
        scroll.setHasVerticalScroller(true);
        scroll.setAutohidesScrollers(true);
        scroll.setDrawsBackground(false);
        let container = NSView::new(mtm);
        widgets::pin(&scroll, &container, 0.0);
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
            collection,
            layout,
            source,
            empty,
        };
        host.size_tiles(props);
        host.show_empty(props);
        host.collection.reloadData();
        host
    }

    pub fn view(&self) -> Retained<NSView> {
        self.container.clone()
    }

    pub fn update(&self, props: &Tiles) {
        let old = std::mem::replace(
            &mut self.source.ivars().data.borrow_mut().tiles,
            props.clone(),
        );
        if old.min_width != props.min_width || old.height != props.height {
            self.size_tiles(props);
        }
        if old.check != props.check || old.test_label != props.test_label {
            self.collection.reloadData();
            self.show_empty(props);
            return;
        }
        match props.tile_changes(&old) {
            KeyedChanges::None => {}
            KeyedChanges::Edit {
                removed,
                inserted,
                changed,
            } if removed.is_empty() && inserted.is_empty() => self.refill(props, &changed),
            _ => self.collection.reloadData(),
        }
        self.show_empty(props);
    }

    /// Gives the tiles that have views their new content; the others take it
    /// when the collection view asks for them.
    fn refill(&self, props: &Tiles, changed: &[usize]) {
        let owner = self.source.ivars().data.borrow().owner;
        for &index in changed {
            let path = NSIndexPath::indexPathForItem_inSection(index as NSInteger, 0);
            let view = self
                .collection
                .itemAtIndexPath(&path)
                .and_then(|item| item.view().downcast::<TileView>().ok());
            if let (Some(view), Some(tile)) = (view, props.tiles.get(index)) {
                view.show(tile, owner, props);
            }
        }
    }

    /// Tiles at least `min_width` wide, sharing what a row has left.
    fn size_tiles(&self, props: &Tiles) {
        self.layout
            .setMinimumItemSize(NSSize::new(props.min_width, props.height));
        self.layout
            .setMaximumItemSize(NSSize::new(f64::from(u16::MAX), props.height));
    }

    fn show_empty(&self, props: &Tiles) {
        let empty = props.tiles.is_empty();
        self.empty.setStringValue(&NSString::from_str(if empty {
            props.empty.as_deref().unwrap_or("")
        } else {
            ""
        }));
        self.empty.setHidden(!empty);
    }
}
