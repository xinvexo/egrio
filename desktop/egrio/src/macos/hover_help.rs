//! Hover help: the short text a control shows while the pointer rests on
//! it. AppKit's tooltips wait about two seconds before the first one shows
//! and have no API for the delay, so controls carry their help here: a
//! tracking area on the control (`NSTrackingArea.h`) reports the pointer
//! coming and going, and one borderless panel in the tooltip material
//! (`NSVisualEffectMaterialToolTip`, macOS 10.14) with the tooltip font
//! (`NSFont toolTipsFontOfSize:`) shows the help [`DELAY`] after the pointer
//! comes to a control, or at once while it moves on from one help to the
//! next. The help hides when the pointer leaves, on a click, a key or a
//! scroll, and once its control is gone from under the pointer. VoiceOver
//! reads the same text as the control's accessibility help.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchTime};
use objc2::ffi::{objc_getAssociatedObject, objc_setAssociatedObject};
use objc2::rc::{Retained, Weak};
use objc2::runtime::{AnyObject, NSObjectProtocol};
use objc2::{
    define_class, msg_send, AllocAnyThread, DeclaredClass, MainThreadMarker, MainThreadOnly,
    Message,
};
use objc2_app_kit::{
    NSAccessibility, NSApplication, NSBackingStoreType, NSColor, NSEvent, NSEventMask, NSFont,
    NSPanel, NSPopUpMenuWindowLevel, NSScreen, NSTextField, NSTrackingArea, NSTrackingAreaOptions,
    NSView, NSVisualEffectMaterial, NSVisualEffectState, NSVisualEffectView,
    NSWindowCollectionBehavior, NSWindowStyleMask,
};
use objc2_foundation::{NSArray, NSObject, NSPoint, NSPointInRect, NSRect, NSSize, NSString};

use super::style;

/// How long the pointer rests on a control before its help shows.
const DELAY: Duration = Duration::from_millis(500);
/// A help that hid this recently lets the next one show at once.
const WARM: Duration = Duration::from_millis(500);
/// How often a shown help checks that its control is still under the
/// pointer: a control taken out of the window sends no exit.
const WATCH: Duration = Duration::from_millis(250);
/// The widest a help gets before its text wraps.
const MAX_WIDTH: f64 = 320.0;
/// The space between a help's edge and its text.
const PADDING: NSSize = NSSize {
    width: 8.0,
    height: 4.0,
};
const RADIUS: f64 = 6.0;
/// A help's top sits this far below the pointer's hot spot, clear of the
/// arrow.
const BELOW_POINTER: f64 = 24.0;

/// The association key of a control's help owner.
static OWNER_KEY: u8 = 0;

fn owner_key() -> *const c_void {
    std::ptr::from_ref(&OWNER_KEY).cast()
}

pub struct OwnerIvars {
    view: Weak<NSView>,
    text: RefCell<Option<String>>,
}

define_class!(
    /// A control's help and the owner of its tracking area. The control
    /// holds it as an associated object, so it lives as long as the control.
    #[unsafe(super(NSObject))]
    #[name = "EgrioHoverHelp"]
    #[thread_kind = MainThreadOnly]
    #[ivars = OwnerIvars]
    struct HelpOwner;

    unsafe impl NSObjectProtocol for HelpOwner {}

    impl HelpOwner {
        #[unsafe(method(mouseEntered:))]
        fn mouse_entered(&self, _event: &NSEvent) {
            with_panel(MainThreadMarker::from(self), |panel| panel.entered(self));
        }

        #[unsafe(method(mouseExited:))]
        fn mouse_exited(&self, _event: &NSEvent) {
            with_panel(MainThreadMarker::from(self), |panel| panel.exited(self));
        }
    }
);

impl HelpOwner {
    fn text(&self) -> Option<String> {
        self.ivars().text.borrow().clone()
    }
}

/// Gives `view` the help `text`, or takes its help away.
pub fn set(view: &NSView, text: Option<&str>) {
    let text = text.filter(|text| !text.is_empty());
    let owner = match owner(view) {
        Some(owner) => owner,
        None if text.is_none() => return,
        None => attach(view),
    };
    if owner.ivars().text.borrow().as_deref() == text {
        return;
    }
    *owner.ivars().text.borrow_mut() = text.map(str::to_owned);
    view.setAccessibilityHelp(text.map(NSString::from_str).as_deref());
    with_panel(MainThreadMarker::from(view), |panel| panel.changed(&owner));
}

/// The help `view` carries, as VoiceOver reads it.
#[cfg(feature = "test-control")]
pub fn of(view: &NSView) -> Option<String> {
    owner(view).and_then(|owner| owner.text())
}

/// The help's window while a help shows.
#[cfg(feature = "test-control")]
pub fn shown_window() -> Option<Retained<objc2_app_kit::NSWindow>> {
    PANEL.with(|panel| {
        let panel = panel.try_borrow().ok()?;
        let panel = panel.as_ref().filter(|panel| panel.shown.is_some())?;
        Some(Retained::into_super(panel.window.clone()))
    })
}

fn owner(view: &NSView) -> Option<Retained<HelpOwner>> {
    // SAFETY: only `attach` sets this key, always to a help owner.
    unsafe {
        let object = objc_getAssociatedObject(std::ptr::from_ref(view).cast(), owner_key());
        Retained::retain(object.cast_mut().cast::<HelpOwner>())
    }
}

/// Tracks the pointer over `view` for a new help owner it keeps.
fn attach(view: &NSView) -> Retained<HelpOwner> {
    let mtm = MainThreadMarker::from(view);
    let owner = HelpOwner::alloc(mtm).set_ivars(OwnerIvars {
        view: Weak::new(view),
        text: RefCell::new(None),
    });
    let owner: Retained<HelpOwner> = unsafe { msg_send![super(owner), init] };
    // The area follows the view's visible rect; its owner is not retained.
    let area = unsafe {
        NSTrackingArea::initWithRect_options_owner_userInfo(
            NSTrackingArea::alloc(),
            NSRect::ZERO,
            NSTrackingAreaOptions::MouseEnteredAndExited
                | NSTrackingAreaOptions::ActiveInActiveApp
                | NSTrackingAreaOptions::InVisibleRect,
            Some(&owner),
            None,
        )
    };
    view.addTrackingArea(&area);
    // SAFETY: the view retains the owner for as long as it lives.
    unsafe {
        objc_setAssociatedObject(
            std::ptr::from_ref(view).cast_mut().cast(),
            owner_key(),
            Retained::as_ptr(&owner).cast_mut().cast(),
            objc2::ffi::OBJC_ASSOCIATION_RETAIN_NONATOMIC,
        );
    }
    owner
}

thread_local! {
    static PANEL: RefCell<Option<Panel>> = const { RefCell::new(None) };
}

/// Runs `work` on the help panel, made on first use. A call that arrives
/// while the panel is busy (AppKit calling back from inside it) is dropped.
fn with_panel(mtm: MainThreadMarker, work: impl FnOnce(&mut Panel)) {
    PANEL.with(|panel| {
        if let Ok(mut panel) = panel.try_borrow_mut() {
            work(panel.get_or_insert_with(|| Panel::new(mtm)));
        }
    });
}

/// Runs `work` on the help panel after `delay`, on the main queue.
fn after(delay: Duration, work: impl FnOnce(&mut Panel) + Send + 'static) {
    let when = DispatchTime::try_from(delay).unwrap_or(DispatchTime::NOW);
    let _ = DispatchQueue::main().after(when, move || {
        if let Some(mtm) = MainThreadMarker::new() {
            with_panel(mtm, work);
        }
    });
}

struct Panel {
    mtm: MainThreadMarker,
    window: Retained<NSPanel>,
    label: Retained<NSTextField>,
    /// The control the pointer rests on, until its help shows.
    waiting: Option<Retained<HelpOwner>>,
    shown: Option<Retained<HelpOwner>>,
    /// Counts the pointer's comings and goings, so a stale timer does
    /// nothing.
    generation: u64,
    hidden_at: Option<Instant>,
    /// A watch over the shown help is scheduled.
    watching: Cell<bool>,
    /// Hides the help on a click, a key or a scroll, while one waits or
    /// shows.
    monitor: Option<Retained<AnyObject>>,
}

impl Panel {
    fn new(mtm: MainThreadMarker) -> Self {
        let window = NSPanel::initWithContentRect_styleMask_backing_defer(
            NSPanel::alloc(mtm),
            NSRect::ZERO,
            NSWindowStyleMask::Borderless | NSWindowStyleMask::NonactivatingPanel,
            NSBackingStoreType::Buffered,
            true,
        );
        unsafe { window.setReleasedWhenClosed(false) };
        window.setIgnoresMouseEvents(true);
        window.setOpaque(false);
        window.setBackgroundColor(Some(&NSColor::clearColor()));
        window.setHasShadow(true);
        window.setLevel(NSPopUpMenuWindowLevel);
        window.setHidesOnDeactivate(true);
        window.setCollectionBehavior(
            NSWindowCollectionBehavior::Transient
                | NSWindowCollectionBehavior::IgnoresCycle
                | NSWindowCollectionBehavior::FullScreenAuxiliary,
        );
        // The rounded material sits in a plain content view: a content
        // view's mask image becomes the window's corner mask, which AppKit
        // asserts on for this panel (`_NSSetWindowCornerMask`, macOS 13).
        let content = NSView::new(mtm);
        let surface = NSVisualEffectView::new(mtm);
        surface.setMaterial(NSVisualEffectMaterial::ToolTip);
        surface.setState(NSVisualEffectState::Active);
        surface.setMaskImage(Some(&style::rounded_mask(RADIUS)));
        super::widgets::pin(&surface, &content, 0.0);
        let label = NSTextField::wrappingLabelWithString(&NSString::from_str(""), mtm);
        label.setFont(Some(&NSFont::toolTipsFontOfSize(0.0)));
        label.setTextColor(Some(&NSColor::labelColor()));
        label.setPreferredMaxLayoutWidth(MAX_WIDTH);
        label.setTranslatesAutoresizingMaskIntoConstraints(false);
        surface.addSubview(&label);
        objc2_app_kit::NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
            label
                .leadingAnchor()
                .constraintEqualToAnchor_constant(&surface.leadingAnchor(), PADDING.width),
            label
                .topAnchor()
                .constraintEqualToAnchor_constant(&surface.topAnchor(), PADDING.height),
        ]));
        window.setContentView(Some(&content));
        Self {
            mtm,
            window,
            label,
            waiting: None,
            shown: None,
            generation: 0,
            hidden_at: None,
            watching: Cell::new(false),
            monitor: None,
        }
    }

    fn entered(&mut self, owner: &HelpOwner) {
        self.generation += 1;
        self.waiting = None;
        if owner.text().is_some() && NSEvent::pressedMouseButtons() == 0 {
            let warm = self.shown.is_some() || self.hidden_at.is_some_and(|at| at.elapsed() < WARM);
            if warm {
                self.show(owner);
            } else {
                self.waiting = Some(owner.retain());
                let generation = self.generation;
                after(DELAY, move |panel| {
                    if panel.generation == generation {
                        if let Some(owner) = panel.waiting.take() {
                            panel.show(&owner);
                        }
                    }
                });
            }
        }
        self.settle_monitor();
    }

    fn exited(&mut self, owner: &HelpOwner) {
        if is(&self.waiting, owner) {
            self.waiting = None;
            self.generation += 1;
        }
        if is(&self.shown, owner) {
            self.hide();
        }
        self.settle_monitor();
    }

    /// The owner's text changed: a shown help shows the new text or hides.
    fn changed(&mut self, owner: &HelpOwner) {
        if owner.text().is_none() && is(&self.waiting, owner) {
            self.waiting = None;
            self.generation += 1;
        }
        if is(&self.shown, owner) {
            self.show(owner);
        }
        self.settle_monitor();
    }

    fn show(&mut self, owner: &HelpOwner) {
        let (Some(text), Some(view)) = (owner.text(), owner.ivars().view.load()) else {
            return self.hide();
        };
        if !pointer_on(&view) {
            return self.hide();
        }
        self.label.setStringValue(&NSString::from_str(&text));
        let fitting = self.label.fittingSize();
        let size = NSSize::new(
            (fitting.width + 2.0 * PADDING.width).ceil(),
            (fitting.height + 2.0 * PADDING.height).ceil(),
        );
        self.window
            .setFrame_display(NSRect::new(self.origin(size), size), true);
        self.window.invalidateShadow();
        self.window.orderFront(None);
        self.waiting = None;
        self.shown = Some(owner.retain());
        self.watch();
    }

    fn hide(&mut self) {
        self.waiting = None;
        self.generation += 1;
        if self.shown.take().is_some() {
            self.window.orderOut(None);
            self.hidden_at = Some(Instant::now());
        }
        self.settle_monitor();
    }

    /// Where a help of `size` goes: under the pointer, inside the screen's
    /// visible area, above the pointer where there is no room under it.
    fn origin(&self, size: NSSize) -> NSPoint {
        let pointer = NSEvent::mouseLocation();
        let mut origin = NSPoint::new(pointer.x, pointer.y - BELOW_POINTER - size.height);
        let visible = NSScreen::screens(self.mtm)
            .iter()
            .find(|screen| NSPointInRect(pointer, screen.frame()))
            .map(|screen| screen.visibleFrame());
        if let Some(visible) = visible {
            let right = visible.origin.x + visible.size.width - size.width;
            origin.x = origin.x.min(right).max(visible.origin.x);
            if origin.y < visible.origin.y {
                origin.y = pointer.y + PADDING.height;
            }
        }
        origin
    }

    /// Hides the shown help once its control is no longer under the
    /// pointer, or the app is no longer active.
    fn watch(&self) {
        if self.watching.replace(true) {
            return;
        }
        after(WATCH, |panel| {
            panel.watching.set(false);
            let Some(owner) = panel.shown.clone() else {
                return;
            };
            let active = NSApplication::sharedApplication(panel.mtm).isActive();
            if active
                && owner
                    .ivars()
                    .view
                    .load()
                    .is_some_and(|view| pointer_on(&view))
            {
                panel.watch();
            } else {
                panel.hide();
            }
        });
    }

    /// Watches clicks, keys and scrolls only while a help waits or shows.
    fn settle_monitor(&mut self) {
        let needed = self.waiting.is_some() || self.shown.is_some();
        match (needed, self.monitor.is_some()) {
            (true, false) => self.monitor = dismiss_monitor(),
            (false, true) => {
                if let Some(monitor) = self.monitor.take() {
                    unsafe { NSEvent::removeMonitor(&monitor) };
                }
            }
            _ => {}
        }
    }
}

fn is(slot: &Option<Retained<HelpOwner>>, owner: &HelpOwner) -> bool {
    slot.as_deref()
        .is_some_and(|held| std::ptr::eq(held, owner))
}

/// A click, a key or a scroll hides the help and goes on to its target.
fn dismiss_monitor() -> Option<Retained<AnyObject>> {
    let handler = RcBlock::new(|event: NonNull<NSEvent>| -> *mut NSEvent {
        if let Some(mtm) = MainThreadMarker::new() {
            with_panel(mtm, Panel::hide);
        }
        event.as_ptr()
    });
    unsafe {
        NSEvent::addLocalMonitorForEventsMatchingMask_handler(
            NSEventMask::LeftMouseDown
                | NSEventMask::RightMouseDown
                | NSEventMask::OtherMouseDown
                | NSEventMask::KeyDown
                | NSEventMask::ScrollWheel,
            &handler,
        )
    }
}

/// Whether the pointer is over the part of `view` its window shows.
fn pointer_on(view: &NSView) -> bool {
    let Some(window) = view.window() else {
        return false;
    };
    if !window.isVisible() || view.isHiddenOrHasHiddenAncestor() {
        return false;
    }
    let point = window.convertPointFromScreen(NSEvent::mouseLocation());
    let local = view.convertPoint_fromView(point, None);
    view.mouse_inRect(local, view.visibleRect())
}
