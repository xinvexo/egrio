//! The menu bar item: a template icon and the tray's menu. Commands and
//! submenus are standard menu items; a group's latency test and its members
//! are rows of their own (`MenuRow`), which draw themselves as Apple's guide
//! to views in menu items asks: a member's latency sits in a column at the
//! end, and choosing the test keeps the menu open so its results land in
//! place.
//! https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/MenuList/Articles/ViewsInMenuItems.html
//!
//! A group's rows exist while its submenu shows (`GroupMenu`). The
//! submenu's delegate makes them in `menuNeedsUpdate:`, which AppKit sends
//! when a menu is about to be displayed and where the delegate may add and
//! remove items (`NSMenuDelegate`, "menuNeedsUpdate(_:)"), and lets them go
//! once the submenu has closed: after `menuDidClose:` returns, since a
//! menu's items may not change inside it (`NSMenu.h`: "Do not modify the
//! structure of the menu or the menu items from within these callbacks").
//! Creating rows only for the visible group bounds native view allocation
//! to the submenu being displayed.
//!
//! A new menu with the same items in the same places changes them in place,
//! so an open menu stays open; any other change builds it again. Changes
//! reach an open menu through the main queue, which the run loop serves in
//! its tracking mode too.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use dispatch2::{DispatchQueue, MainThreadBound};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, AnyThread, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSAccessibility, NSAccessibilityMenuItemRole, NSAutoresizingMaskOptions, NSBezierPath, NSColor,
    NSControlStateValueOff, NSControlStateValueOn, NSEvent, NSFont, NSFontAttributeName,
    NSForegroundColorAttributeName, NSImage, NSLineBreakMode, NSMenu, NSMenuDelegate, NSMenuItem,
    NSMutableParagraphStyle, NSParagraphStyleAttributeName, NSStatusBar, NSStatusItem,
    NSStringDrawing, NSTextAlignment, NSTrackingArea, NSTrackingAreaOptions,
    NSVariableStatusItemLength, NSView,
};
use objc2_foundation::{
    NSAttributedStringKey, NSData, NSDictionary, NSPoint, NSRect, NSSize, NSString,
};

use egrio_ui::backend::{TrayAction, TrayGroup, TrayItem, TrayLatency, TrayView, UiEvent};
use egrio_ui::node::Tone;

use super::style;
use super::target::ActionTarget;

/// The menu bar's snowflake: template images AppKit draws in the menu bar's
/// own color, the one without capture at 42% opacity. Each stays still until
/// the state changes.
const ICON: &[u8] = include_bytes!("../../icons/tray-macos-on.png");
const ICON_OFF: &[u8] = include_bytes!("../../icons/tray-macos-off.png");
/// A row's text starts after the check column and ends before the latency.
const LEFT: f64 = 24.0;
const RIGHT: f64 = 12.0;
const LATENCY_WIDTH: f64 = 58.0;
const GAP: f64 = 10.0;
/// What a column leaves free at each end of its text.
const PAD: f64 = 2.0;

/// What choosing a row does: the group's latency test, or the choice of
/// one of its members. The action is named when the row is chosen.
#[derive(Clone)]
enum Chooses {
    Test(Arc<TrayGroup>),
    Member(Arc<TrayGroup>, usize),
}

impl Chooses {
    fn action(&self) -> Option<TrayAction> {
        match self {
            Self::Test(group) => Some(group.test()),
            Self::Member(group, index) => {
                group.members.get(*index).map(|member| group.select(member))
            }
        }
    }
}

/// What the rows of one submenu share: their fonts and their measures.
struct RowLook {
    font: Retained<NSFont>,
    /// The latency column's font, whose digits are all one width.
    digits: Retained<NSFont>,
    /// A title that does not fit ends in an ellipsis.
    cut: Retained<NSMutableParagraphStyle>,
    /// A latency ends where its column does.
    trailing: Retained<NSMutableParagraphStyle>,
    width: f64,
    height: f64,
    /// The height of a line of text in a row.
    line: f64,
}

impl RowLook {
    /// For a submenu of rows with these titles: room for the longest one
    /// and the latency column.
    fn of<'a>(menu: &NSMenu, titles: impl Iterator<Item = Cow<'a, str>>) -> Self {
        let font = menu.font().unwrap_or_else(|| NSFont::menuFontOfSize(0.0));
        let keys: [&NSAttributedStringKey; 1] = [unsafe { NSFontAttributeName }];
        let values: [&AnyObject; 1] = [font.as_ref()];
        let attributes = NSDictionary::from_slices(&keys, &values);
        // SAFETY: the dictionary maps the font attribute to a font.
        let size =
            |text: &str| unsafe { NSString::from_str(text).sizeWithAttributes(Some(&attributes)) };
        let widest = titles
            .map(|title| size(&title).width)
            .fold(0.0, f64::max)
            .ceil();
        let cut = NSMutableParagraphStyle::new();
        cut.setLineBreakMode(NSLineBreakMode::ByTruncatingTail);
        let trailing = NSMutableParagraphStyle::new();
        trailing.setAlignment(NSTextAlignment::Right);
        Self {
            digits: NSFont::monospacedDigitSystemFontOfSize_weight(font.pointSize(), 0.0),
            cut,
            trailing,
            width: (LEFT + widest + 2.0 * PAD + GAP + LATENCY_WIDTH + RIGHT).clamp(180.0, 420.0),
            height: (font.pointSize() + 9.0).max(22.0),
            line: size("0").height.ceil().max(font.pointSize() + 4.0),
            font,
        }
    }

    /// Draws `text` on the row's line, from `x` and `width` wide.
    fn draw(
        &self,
        text: &NSString,
        x: f64,
        width: f64,
        font: &NSFont,
        color: &NSColor,
        paragraph: &NSMutableParagraphStyle,
    ) {
        let keys: [&NSAttributedStringKey; 3] = unsafe {
            [
                NSFontAttributeName,
                NSForegroundColorAttributeName,
                NSParagraphStyleAttributeName,
            ]
        };
        let values: [&AnyObject; 3] = [font.as_ref(), color.as_ref(), paragraph.as_ref()];
        let attributes = NSDictionary::from_slices(&keys, &values);
        let line = NSRect::new(
            NSPoint::new(x + PAD, (self.height - self.line) / 2.0),
            NSSize::new((width - 2.0 * PAD).max(0.0), self.line),
        );
        // SAFETY: the dictionary maps each attribute to a value of its kind.
        unsafe { text.drawInRect_withAttributes(line, Some(&attributes)) };
    }
}

pub struct RowIvars {
    post: fn(UiEvent),
    look: Rc<RowLook>,
    chooses: RefCell<Option<Chooses>>,
    /// Choosing it keeps the menu open.
    keeps_open: bool,
    enabled: Cell<bool>,
    hovered: Cell<bool>,
    checked: Cell<bool>,
    title: RefCell<Retained<NSString>>,
    /// The latency and the color that rates it.
    latency: RefCell<Option<(Retained<NSString>, Tone)>>,
}

define_class!(
    /// A row of a group's submenu: a check column, the title and a latency
    /// column, which the row draws itself, and it takes every click.
    #[unsafe(super(NSView))]
    #[name = "EgrioTrayRow"]
    #[thread_kind = MainThreadOnly]
    #[ivars = RowIvars]
    pub struct MenuRow;

    unsafe impl NSObjectProtocol for MenuRow {}

    impl MenuRow {
        #[unsafe(method(mouseDown:))]
        fn mouse_down(&self, _event: &NSEvent) {}

        #[unsafe(method(mouseUp:))]
        fn mouse_up(&self, event: &NSEvent) {
            let point = self.convertPoint_fromView(event.locationInWindow(), None);
            if self.mouse_inRect(point, self.bounds()) {
                self.activate();
            }
        }

        #[unsafe(method(mouseEntered:))]
        fn mouse_entered(&self, _event: &NSEvent) {
            self.ivars().hovered.set(true);
            self.setNeedsDisplay(true);
        }

        #[unsafe(method(mouseExited:))]
        fn mouse_exited(&self, _event: &NSEvent) {
            self.ivars().hovered.set(false);
            self.setNeedsDisplay(true);
        }

        #[unsafe(method(viewDidMoveToWindow))]
        fn view_did_move_to_window(&self) {
            let _: () = unsafe { msg_send![super(self), viewDidMoveToWindow] };
            // A menu that closes takes its rows out of its window.
            if self.window().is_none() {
                self.ivars().hovered.set(false);
                self.setNeedsDisplay(true);
            }
        }

        #[unsafe(method(accessibilityPerformPress))]
        fn accessibility_perform_press(&self) -> bool {
            self.activate()
        }

        #[unsafe(method(drawRect:))]
        fn draw_rect(&self, _dirty: NSRect) {
            let ivars = self.ivars();
            let look = &ivars.look;
            let bounds = self.bounds();
            let lit = self.lit();
            if lit {
                NSColor::controlAccentColor().setFill();
                NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(
                    NSRect::new(
                        NSPoint::new(5.0, 0.0),
                        NSSize::new((bounds.size.width - 10.0).max(0.0), bounds.size.height),
                    ),
                    4.0,
                    4.0,
                )
                .fill();
            }
            let text = if lit {
                NSColor::selectedMenuItemTextColor()
            } else if ivars.enabled.get() {
                NSColor::labelColor()
            } else {
                NSColor::disabledControlTextColor()
            };
            if ivars.checked.get() {
                look.draw(&NSString::from_str("✓"), 9.0, 15.0, &look.font, &text, &look.cut);
            }
            // A test row has no latency, so its title takes the whole row.
            let title_width = if ivars.keeps_open {
                bounds.size.width - LEFT - RIGHT
            } else {
                bounds.size.width - LEFT - RIGHT - LATENCY_WIDTH - GAP
            };
            look.draw(&ivars.title.borrow(), LEFT, title_width, &look.font, &text, &look.cut);
            if let Some((latency, tone)) = ivars.latency.borrow().as_ref() {
                // A lit row's latency takes the row's color.
                let color = if lit { text.clone() } else { style::color(*tone) };
                look.draw(
                    latency,
                    bounds.size.width - RIGHT - LATENCY_WIDTH,
                    LATENCY_WIDTH,
                    &look.digits,
                    &color,
                    &look.trailing,
                );
            }
        }
    }
);

impl MenuRow {
    fn new(
        mtm: MainThreadMarker,
        keeps_open: bool,
        look: &Rc<RowLook>,
        post: fn(UiEvent),
    ) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(RowIvars {
            post,
            look: look.clone(),
            chooses: RefCell::new(None),
            keeps_open,
            enabled: Cell::new(true),
            hovered: Cell::new(false),
            checked: Cell::new(false),
            title: RefCell::new(NSString::new()),
            latency: RefCell::new(None),
        });
        let this: Retained<Self> = unsafe {
            msg_send![super(this), initWithFrame: NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(look.width, look.height))]
        };
        this.setAutoresizingMask(NSAutoresizingMaskOptions::ViewWidthSizable);
        let area = unsafe {
            NSTrackingArea::initWithRect_options_owner_userInfo(
                NSTrackingArea::alloc(),
                NSRect::ZERO,
                NSTrackingAreaOptions::MouseEnteredAndExited
                    | NSTrackingAreaOptions::ActiveAlways
                    | NSTrackingAreaOptions::InVisibleRect
                    | NSTrackingAreaOptions::EnabledDuringMouseDrag,
                Some(this.as_ref() as &AnyObject),
                None,
            )
        };
        this.addTrackingArea(&area);
        this.setAccessibilityElement(true);
        this.setAccessibilityRole(Some(unsafe { NSAccessibilityMenuItemRole }));
        this
    }

    /// Whether the row shows lit, under the pointer or picked by the keyboard.
    fn lit(&self) -> bool {
        let picked = self
            .enclosingMenuItem()
            .is_some_and(|item| item.isHighlighted());
        (self.ivars().hovered.get() || picked) && self.ivars().enabled.get()
    }

    fn show(
        &self,
        chooses: Chooses,
        title: &str,
        enabled: bool,
        checked: bool,
        latency: Option<TrayLatency>,
    ) {
        let ivars = self.ivars();
        *ivars.chooses.borrow_mut() = Some(chooses);
        ivars.enabled.set(enabled);
        if let Some(item) = self.enclosingMenuItem() {
            item.setEnabled(enabled);
        }
        ivars.checked.set(checked);
        let latency = latency.map(|latency| (latency.text(), latency.tone()));
        let label = match &latency {
            Some((latency, _)) => format!("{title} {latency}"),
            None => title.to_string(),
        };
        *ivars.title.borrow_mut() = NSString::from_str(title);
        *ivars.latency.borrow_mut() = latency.map(|(text, tone)| (NSString::from_str(&text), tone));
        self.setAccessibilityLabel(Some(&NSString::from_str(&label)));
        self.setAccessibilityEnabled(enabled);
        self.setNeedsDisplay(true);
    }

    fn activate(&self) -> bool {
        if !self.ivars().enabled.get() {
            return false;
        }
        if !self.ivars().keeps_open {
            // Choosing a member closes the menu as any item does.
            // The item's menu is the submenu this row is in.
            if let Some(menu) = self
                .enclosingMenuItem()
                .and_then(|item| unsafe { item.menu() })
            {
                menu.cancelTracking();
            }
        }
        let action = self
            .ivars()
            .chooses
            .borrow()
            .as_ref()
            .and_then(Chooses::action);
        if let Some(action) = action {
            (self.ivars().post)(UiEvent::Tray(action));
        }
        true
    }

    /// What the row shows, for test control: the check, the title and the
    /// latency.
    #[cfg(feature = "test-control")]
    fn shown(&self) -> (bool, String, String) {
        let ivars = self.ivars();
        (
            ivars.checked.get(),
            ivars.title.borrow().to_string(),
            ivars
                .latency
                .borrow()
                .as_ref()
                .map(|(text, _)| text.to_string())
                .unwrap_or_default(),
        )
    }
}

pub struct GroupIvars {
    post: fn(UiEvent),
    /// The group's submenu, empty while it is closed.
    menu: Retained<NSMenu>,
    group: RefCell<Arc<TrayGroup>>,
    /// The shown submenu's rows: the test's, then the members'.
    rows: RefCell<Vec<Retained<MenuRow>>>,
    /// From the submenu being about to show until it has closed.
    shown: Cell<bool>,
}

define_class!(
    /// A policy group's submenu and its delegate: the rows are made when
    /// the submenu is about to show and dropped after it has closed.
    #[unsafe(super(NSObject))]
    #[name = "EgrioTrayGroup"]
    #[thread_kind = MainThreadOnly]
    #[ivars = GroupIvars]
    pub struct GroupMenu;

    unsafe impl NSObjectProtocol for GroupMenu {}

    unsafe impl NSMenuDelegate for GroupMenu {
        #[unsafe(method(menuNeedsUpdate:))]
        fn menu_needs_update(&self, _menu: &NSMenu) {
            self.ivars().shown.set(true);
            self.fill();
        }

        #[unsafe(method(menuDidClose:))]
        fn menu_did_close(&self, _menu: &NSMenu) {
            self.ivars().shown.set(false);
            // The items may not change inside this callback, and the
            // submenu may be about to show again when the queue gets here.
            let mtm = MainThreadMarker::from(self);
            let this = MainThreadBound::new(objc2::Message::retain(self), mtm);
            DispatchQueue::main().exec_async(move || {
                let mtm = MainThreadMarker::new().expect("main queue");
                this.get(mtm).empty_unless_shown();
            });
        }
    }
);

impl GroupMenu {
    fn new(mtm: MainThreadMarker, group: &Arc<TrayGroup>, post: fn(UiEvent)) -> Retained<Self> {
        let menu = NSMenu::new(mtm);
        // Items take the states the interface gives them.
        menu.setAutoenablesItems(false);
        let this = Self::alloc(mtm).set_ivars(GroupIvars {
            post,
            menu,
            group: RefCell::new(group.clone()),
            rows: RefCell::new(Vec::new()),
            shown: Cell::new(false),
        });
        let this: Retained<Self> = unsafe { msg_send![super(this), init] };
        this.ivars()
            .menu
            .setDelegate(Some(ProtocolObject::from_ref(&*this)));
        this
    }

    /// Makes the rows the submenu shows, unless it has them.
    pub fn fill(&self) {
        let ivars = self.ivars();
        if !ivars.rows.borrow().is_empty() {
            return;
        }
        let mtm = MainThreadMarker::from(self);
        let group = ivars.group.borrow().clone();
        let titles = std::iter::once(group.test_label.into())
            .chain(group.members.iter().map(|member| member.label()));
        let look = Rc::new(RowLook::of(&ivars.menu, titles));
        let mut rows = Vec::with_capacity(group.members.len() + 1);
        for place in 0..=group.members.len() {
            let row = MenuRow::new(mtm, place == 0, &look, ivars.post);
            let entry = NSMenuItem::new(mtm);
            entry.setView(Some(&row));
            ivars.menu.addItem(&entry);
            if place == 0 {
                ivars.menu.addItem(&NSMenuItem::separatorItem(mtm));
            }
            rows.push(row);
        }
        *ivars.rows.borrow_mut() = rows;
        self.restyle();
    }

    /// Drops the rows of a submenu that does not show.
    pub fn empty_unless_shown(&self) {
        let ivars = self.ivars();
        if !ivars.shown.get() {
            ivars.menu.removeAllItems();
            ivars.rows.borrow_mut().clear();
        }
    }

    /// Takes the group as it now is. An open submenu shows it at once: in
    /// its rows when the members are the same ones, in new rows otherwise.
    fn show(&self, group: &Arc<TrayGroup>) {
        let ivars = self.ivars();
        let before = ivars.group.replace(group.clone());
        if ivars.rows.borrow().is_empty() || Arc::ptr_eq(&before, group) {
            return;
        }
        let same_members = before.members.len() == group.members.len()
            && before
                .members
                .iter()
                .zip(&group.members)
                .all(|(old, new)| old.name == new.name && old.badge == new.badge);
        if same_members {
            self.restyle();
        } else {
            ivars.menu.removeAllItems();
            ivars.rows.borrow_mut().clear();
            self.fill();
        }
    }

    /// Gives the rows the titles and states of the group.
    fn restyle(&self) {
        let ivars = self.ivars();
        let group = ivars.group.borrow().clone();
        let rows = ivars.rows.borrow();
        let Some((test, members)) = rows.split_first() else {
            return;
        };
        test.show(
            Chooses::Test(group.clone()),
            group.test_label,
            group.test_enabled,
            false,
            None,
        );
        for (index, (row, member)) in members.iter().zip(&group.members).enumerate() {
            row.show(
                Chooses::Member(group.clone(), index),
                &member.label(),
                member.enabled,
                member.checked,
                member.latency,
            );
        }
    }
}

/// The views behind one item of the menu.
enum Native {
    Command {
        item: Retained<NSMenuItem>,
        _target: Retained<ActionTarget>,
        action: std::rc::Rc<RefCell<TrayAction>>,
    },
    Submenu {
        item: Retained<NSMenuItem>,
        children: Vec<Native>,
    },
    Group {
        item: Retained<NSMenuItem>,
        group: Retained<GroupMenu>,
    },
    Separator,
}

/// Whether two menus have the same items in the same places, whatever their
/// titles and states, and whatever members their groups have.
fn same_shape(old: &[TrayItem], new: &[TrayItem]) -> bool {
    old.len() == new.len()
        && old.iter().zip(new).all(|pair| match pair {
            (TrayItem::Command { action: a, .. }, TrayItem::Command { action: b, .. }) => a == b,
            (TrayItem::Submenu { items: a, .. }, TrayItem::Submenu { items: b, .. }) => {
                same_shape(a, b)
            }
            (TrayItem::Group(a), TrayItem::Group(b)) => {
                a.profile_id == b.profile_id && a.group_id == b.group_id
            }
            (TrayItem::Separator, TrayItem::Separator) => true,
            _ => false,
        })
}

#[cfg(feature = "test-control")]
thread_local! {
    /// The status item, which test control reads and opens.
    static SHOWN: RefCell<Option<Retained<NSStatusItem>>> = const { RefCell::new(None) };
}

/// The status item, for test control.
#[cfg(feature = "test-control")]
pub fn status_item() -> Option<Retained<NSStatusItem>> {
    SHOWN.with(|shown| shown.borrow().clone())
}

pub struct Tray {
    item: Retained<NSStatusItem>,
    view: TrayView,
    post: fn(UiEvent),
    items: Vec<Native>,
}

/// Shows on the status item's button whether traffic goes through Egrio.
fn show_connection(item: &NSStatusItem, mtm: MainThreadMarker, connected: bool) {
    let bytes = if connected { ICON } else { ICON_OFF };
    let image = NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(bytes));
    if let (Some(button), Some(image)) = (item.button(mtm), image) {
        image.setTemplate(true);
        image.setSize(NSSize::new(22.0, 22.0));
        button.setImage(Some(&image));
    }
}

impl Tray {
    pub fn new(mtm: MainThreadMarker, view: &TrayView, post: fn(UiEvent)) -> Self {
        let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
        show_connection(&item, mtm, view.connected);
        if let Some(button) = item.button(mtm) {
            button.setToolTip(Some(&NSString::from_str(&view.tooltip)));
        }
        #[cfg(feature = "test-control")]
        SHOWN.with(|shown| *shown.borrow_mut() = Some(item.clone()));
        let mut tray = Self {
            item,
            view: view.clone(),
            post,
            items: Vec::new(),
        };
        tray.build(mtm);
        tray
    }

    pub fn update(&mut self, mtm: MainThreadMarker, view: &TrayView) {
        if *view == self.view {
            return;
        }
        if view.connected != self.view.connected {
            show_connection(&self.item, mtm, view.connected);
        }
        let in_place = same_shape(&self.view.items, &view.items);
        self.view = view.clone();
        if in_place {
            restyle(&self.items, &self.view.items);
        } else {
            self.build(mtm);
        }
    }

    fn build(&mut self, mtm: MainThreadMarker) {
        let (menu, items) = build_menu(mtm, &self.view.items, self.post);
        self.item.setMenu(Some(&menu));
        self.items = items;
    }
}

fn build_menu(
    mtm: MainThreadMarker,
    items: &[TrayItem],
    post: fn(UiEvent),
) -> (Retained<NSMenu>, Vec<Native>) {
    let menu = NSMenu::new(mtm);
    // Items take the states the interface gives them.
    menu.setAutoenablesItems(false);
    let mut natives = Vec::new();
    for item in items {
        let native = match item {
            TrayItem::Command { action, .. } => {
                let shared = std::rc::Rc::new(RefCell::new(action.clone()));
                let pressed = shared.clone();
                let target = ActionTarget::new(mtm, move |_| {
                    post(UiEvent::Tray(pressed.borrow().clone()));
                });
                let entry = unsafe {
                    NSMenuItem::initWithTitle_action_keyEquivalent(
                        NSMenuItem::alloc(mtm),
                        &NSString::from_str(""),
                        Some(ActionTarget::selector()),
                        &NSString::from_str(""),
                    )
                };
                let object: &AnyObject = target.as_ref();
                unsafe { entry.setTarget(Some(object)) };
                menu.addItem(&entry);
                Native::Command {
                    item: entry,
                    _target: target,
                    action: shared,
                }
            }
            TrayItem::Submenu { label, items, .. } => {
                let entry = NSMenuItem::new(mtm);
                entry.setTitle(&NSString::from_str(label));
                let (submenu, children) = build_menu(mtm, items, post);
                submenu.setTitle(&NSString::from_str(label));
                entry.setSubmenu(Some(&submenu));
                menu.addItem(&entry);
                Native::Submenu {
                    item: entry,
                    children,
                }
            }
            TrayItem::Group(group) => {
                let entry = NSMenuItem::new(mtm);
                let group = GroupMenu::new(mtm, group, post);
                entry.setSubmenu(Some(&group.ivars().menu));
                menu.addItem(&entry);
                Native::Group { item: entry, group }
            }
            TrayItem::Separator => {
                menu.addItem(&NSMenuItem::separatorItem(mtm));
                Native::Separator
            }
        };
        natives.push(native);
    }
    restyle(&natives, items);
    (menu, natives)
}

/// Gives the views the titles and states of `items`, which have the shape
/// the views were built for.
fn restyle(natives: &[Native], items: &[TrayItem]) {
    for (native, item) in natives.iter().zip(items) {
        match (native, item) {
            (
                Native::Command {
                    item: entry,
                    action: shared,
                    ..
                },
                TrayItem::Command {
                    label,
                    action,
                    enabled,
                    checked,
                },
            ) => {
                entry.setTitle(&NSString::from_str(label));
                entry.setEnabled(*enabled);
                entry.setState(if *checked {
                    NSControlStateValueOn
                } else {
                    NSControlStateValueOff
                });
                *shared.borrow_mut() = action.clone();
            }
            (
                Native::Submenu {
                    item: entry,
                    children,
                },
                TrayItem::Submenu {
                    label,
                    enabled,
                    items,
                },
            ) => {
                entry.setTitle(&NSString::from_str(label));
                entry.setEnabled(*enabled);
                restyle(children, items);
            }
            (Native::Group { item: entry, group }, TrayItem::Group(shown)) => {
                let title = NSString::from_str(&shown.label);
                entry.setTitle(&title);
                group.ivars().menu.setTitle(&title);
                entry.setEnabled(shown.enabled);
                group.show(shown);
            }
            _ => {}
        }
    }
}

/// A group's submenu with its rows made, as opening it makes them, for
/// test control; `None` for any other menu.
#[cfg(feature = "test-control")]
fn shown_group(menu: &NSMenu) -> Option<Retained<GroupMenu>> {
    let delegate = menu.delegate()?;
    let object: &AnyObject = (*delegate).as_ref();
    let group = object.downcast_ref::<GroupMenu>()?;
    group.fill();
    Some(objc2::Message::retain(group))
}

/// The groups of a menu, in its order, for test control.
#[cfg(feature = "test-control")]
fn groups(menu: &NSMenu) -> Vec<Retained<GroupMenu>> {
    let items = menu.itemArray();
    items
        .iter()
        .filter_map(|item| {
            let delegate = item.submenu()?.delegate()?;
            let object: &AnyObject = (*delegate).as_ref();
            object
                .downcast_ref::<GroupMenu>()
                .map(objc2::Message::retain)
        })
        .collect()
}

/// Hands `draw` the rows of a group for test control: the window of the
/// submenu that shows, or else the first group's rows as its submenu would
/// show them, one under the other in a view of their own, which opens no
/// menu on the desktop.
#[cfg(feature = "test-control")]
pub fn with_group_rows<R>(
    mtm: MainThreadMarker,
    menu: &NSMenu,
    draw: impl FnOnce(&NSView) -> R,
) -> Option<R> {
    let groups = groups(menu);
    let shown = groups.iter().find_map(|group| {
        let rows = group.ivars().rows.borrow();
        rows.first()?.window()?.contentView()
    });
    if let Some(content) = shown {
        let frame = unsafe { content.superview() }.unwrap_or(content);
        return Some(draw(&frame));
    }
    let group = groups.first()?;
    group.fill();
    // The rows leave their items, which place their views themselves, and
    // the submenu makes new ones when it shows.
    group.ivars().menu.removeAllItems();
    let rows = group.ivars().rows.take();
    let size = rows.first()?.frame().size;
    let sheet = NSView::initWithFrame(
        NSView::alloc(mtm),
        NSRect::new(
            NSPoint::new(0.0, 0.0),
            NSSize::new(size.width, size.height * rows.len() as f64),
        ),
    );
    for (place, row) in rows.iter().rev().enumerate() {
        sheet.addSubview(row);
        row.setFrame(NSRect::new(
            NSPoint::new(0.0, size.height * place as f64),
            size,
        ));
    }
    Some(draw(&sheet))
}

/// The titles and states of a menu, one item per line, for test control.
#[cfg(feature = "test-control")]
pub fn describe(menu: &NSMenu, depth: usize, lines: &mut Vec<String>) {
    for item in menu.itemArray().iter() {
        let indent = "  ".repeat(depth);
        if item.isSeparatorItem() {
            lines.push(format!("{indent}-"));
            continue;
        }
        let enabled = if item.isEnabled() { "" } else { " disabled" };
        if let Some(row) = item.view().and_then(|view| view.downcast::<MenuRow>().ok()) {
            let (checked, title, latency) = row.shown();
            let check = if checked { "✓" } else { "" };
            lines.push(format!("{indent}{check}{title} [{latency}]{enabled}"));
            continue;
        }
        let check = if item.state() == NSControlStateValueOn {
            "✓"
        } else {
            ""
        };
        lines.push(format!("{indent}{check}{}{enabled}", item.title()));
        if let Some(submenu) = item.submenu() {
            let group = shown_group(&submenu);
            describe(&submenu, depth + 1, lines);
            if let Some(group) = group {
                group.empty_unless_shown();
            }
        }
    }
}

/// Chooses the item titled `title`, anywhere in the menu, as a click does.
#[cfg(feature = "test-control")]
pub fn choose(menu: &NSMenu, title: &str) -> bool {
    for (index, item) in menu.itemArray().iter().enumerate() {
        if let Some(row) = item.view().and_then(|view| view.downcast::<MenuRow>().ok()) {
            if row.shown().1 == title {
                return row.activate();
            }
            continue;
        }
        if item.title().to_string() == title && item.submenu().is_none() {
            if !item.isEnabled() {
                return false;
            }
            menu.performActionForItemAtIndex(index as isize);
            return true;
        }
        if let Some(submenu) = item.submenu() {
            let group = shown_group(&submenu);
            let chosen = choose(&submenu, title);
            if let Some(group) = group {
                group.empty_unless_shown();
            }
            if chosen {
                return true;
            }
        }
    }
    false
}
