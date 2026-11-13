//! The main window's shell: a split view with the sidebar of sections and
//! the page, under a unified toolbar that carries the capture switches and
//! the traffic mode at its trailing end. The band the title bar leaves over
//! the page shows no page title, the sidebar's selection names the page; the
//! message capsule starts it, in line with the page, in the title bar's own
//! view, outside the toolbar, so the toolbar's item backgrounds never take it
//! in. The message panel grows out of the capsule over the page
//! (`messages.rs`).

use std::cell::{Cell, RefCell};
use std::ptr::NonNull;

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObjectProtocol, ProtocolObject};
use objc2::{
    define_class, msg_send, ClassType, DeclaredClass, MainThreadMarker, MainThreadOnly, Message,
};
use objc2_app_kit::{
    NSAppearanceCustomization, NSAppearanceNameAqua, NSAppearanceNameDarkAqua, NSBackingStoreType,
    NSBezelStyle, NSButton, NSButtonType, NSCellImagePosition, NSColor, NSControlSize,
    NSControlStateValueOff, NSControlStateValueOn, NSControlTextEditingDelegate, NSEvent,
    NSEventMask, NSImageView, NSLayoutConstraint, NSResponder, NSScrollView,
    NSSegmentSwitchTracking, NSSegmentedControl, NSSplitView, NSSplitViewController,
    NSSplitViewDividerStyle, NSSplitViewItem, NSTableCellView, NSTableColumn, NSTableView,
    NSTableViewDataSource, NSTableViewDelegate, NSTableViewStyle, NSTextField, NSTextView,
    NSTitlebarSeparatorStyle, NSToolbar, NSToolbarDelegate, NSToolbarDisplayMode,
    NSToolbarFlexibleSpaceItemIdentifier, NSToolbarItem, NSToolbarItemIdentifier, NSView,
    NSViewController, NSVisualEffectBlendingMode, NSVisualEffectMaterial, NSVisualEffectState,
    NSVisualEffectView, NSWindow, NSWindowDelegate, NSWindowStyleMask, NSWindowTitleVisibility,
    NSWindowToolbarStyle,
};
use objc2_foundation::{
    NSArray, NSCopying, NSEdgeInsets, NSInteger, NSNotification, NSObject, NSPoint, NSPointInRect,
    NSRect, NSSize, NSString,
};

use egrio_ui::backend::{
    CaptureToggle, MainView, NavItem, PolicyControl, ToggleState, ToolbarAction, UiEvent,
    PAGE_MIN_WIDTH,
};
use egrio_ui::reconcile::Mounted;

use super::panels::Dialog;
use super::style;
use super::target::ActionTarget;
use super::widgets::Surface;

/// The page's distance from the sidebar, which the message capsule keeps
/// too.
const PAGE_LEADING: f64 = 20.0;
const DRAWER_INSET: f64 = 16.0;
/// The message panel's least distance from the window's bottom edge, and
/// its messages' distance from the title bar above them.
const DRAWER_MARGIN: f64 = 10.0;
const DRAWER_GAP: f64 = 4.0;
/// The page's distance from its pane's edges, which the message panel
/// keeps from the window's bottom edge too; on the right the page takes the
/// toolbar's own inset once AppKit has placed it, so their ends line up.
const PAGE_INSETS: NSEdgeInsets = NSEdgeInsets {
    top: DRAWER_MARGIN,
    left: PAGE_LEADING,
    bottom: DRAWER_MARGIN,
    right: DRAWER_MARGIN,
};
/// The sidebar's one width; the page takes the rest of the window.
const SIDEBAR_WIDTH: f64 = 180.0;
/// The Escape key's virtual key code, `kVK_Escape` in HIToolbox's `Events.h`.
const ESCAPE: u16 = 0x35;

pub struct WindowIvars {
    post: fn(UiEvent),
    /// Fits the message capsule and its panel to the window again when it
    /// resizes.
    resized: RefCell<Option<Box<dyn Fn()>>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioWindowDelegate"]
    #[thread_kind = MainThreadOnly]
    #[ivars = WindowIvars]
    pub struct WindowDelegate;

    unsafe impl NSObjectProtocol for WindowDelegate {}

    unsafe impl NSWindowDelegate for WindowDelegate {
        #[unsafe(method(windowWillClose:))]
        fn window_will_close(&self, _notification: &NSNotification) {
            (self.ivars().post)(UiEvent::WindowClosed);
        }

        #[unsafe(method(windowDidResize:))]
        fn window_did_resize(&self, _notification: &NSNotification) {
            if let Some(resized) = self.ivars().resized.borrow().as_ref() {
                resized();
            }
        }
    }
);

/// A sidebar row: the section's symbol and name.
fn section_cell(mtm: MainThreadMarker, item: &NavItem) -> Retained<NSView> {
    let cell = NSTableCellView::new(mtm);
    let image = NSImageView::new(mtm);
    image.setImage(style::symbol(item.icon).as_deref());
    let text = NSTextField::labelWithString(&NSString::from_str(&item.label), mtm);
    for view in [image.as_ref() as &NSView, text.as_ref()] {
        view.setTranslatesAutoresizingMaskIntoConstraints(false);
        cell.addSubview(view);
    }
    objc2_app_kit::NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        image
            .leadingAnchor()
            .constraintEqualToAnchor_constant(&cell.leadingAnchor(), 4.0),
        image
            .centerYAnchor()
            .constraintEqualToAnchor(&cell.centerYAnchor()),
        image.widthAnchor().constraintEqualToConstant(18.0),
        text.leadingAnchor()
            .constraintEqualToAnchor_constant(&image.trailingAnchor(), 8.0),
        text.trailingAnchor()
            .constraintLessThanOrEqualToAnchor_constant(&cell.trailingAnchor(), -4.0),
        text.centerYAnchor()
            .constraintEqualToAnchor(&cell.centerYAnchor()),
    ]));
    // The outlets are weak; the views are the cell's subviews, which keep them.
    unsafe {
        cell.setImageView(Some(&image));
        cell.setTextField(Some(&text));
    }
    Retained::into_super(cell)
}

pub struct SidebarIvars {
    items: RefCell<Vec<NavItem>>,
    post: fn(UiEvent),
    quiet: Cell<bool>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioSidebarController"]
    #[thread_kind = MainThreadOnly]
    #[ivars = SidebarIvars]
    pub struct SidebarController;

    unsafe impl NSObjectProtocol for SidebarController {}

    unsafe impl NSControlTextEditingDelegate for SidebarController {}

    unsafe impl NSTableViewDataSource for SidebarController {
        #[unsafe(method(numberOfRowsInTableView:))]
        fn number_of_rows(&self, _table: &NSTableView) -> NSInteger {
            self.ivars().items.borrow().len() as NSInteger
        }
    }

    unsafe impl NSTableViewDelegate for SidebarController {
        #[unsafe(method_id(tableView:viewForTableColumn:row:))]
        fn view_for(
            &self,
            _table: &NSTableView,
            _column: Option<&NSTableColumn>,
            row: NSInteger,
        ) -> Option<Retained<NSView>> {
            log::debug!("sidebar row {row}");
            let item = usize::try_from(row)
                .ok()
                .and_then(|row| self.ivars().items.borrow().get(row).cloned());
            item.map(|item| section_cell(MainThreadMarker::from(self), &item))
        }

        #[unsafe(method(tableViewSelectionDidChange:))]
        fn selection_changed(&self, notification: &NSNotification) {
            if self.ivars().quiet.get() {
                return;
            }
            let Some(object) = notification.object() else {
                return;
            };
            let table: &NSTableView =
                unsafe { &*(Retained::as_ptr(&object) as *const NSTableView) };
            let row = table.selectedRow();
            if let Some(item) = usize::try_from(row)
                .ok()
                .and_then(|row| self.ivars().items.borrow().get(row).cloned())
            {
                (self.ivars().post)(UiEvent::Navigate(item.section));
            }
        }
    }
);

const SYSTEM_PROXY: &str = "egrio.systemProxy";
const TUN: &str = "egrio.tun";
const POLICY: &str = "egrio.policy";

pub struct ToolbarIvars {
    system_proxy: Retained<NSButton>,
    tun: Retained<NSButton>,
    policy: Retained<NSSegmentedControl>,
    has_system_proxy: Cell<bool>,
    _targets: Vec<Retained<ActionTarget>>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioToolbarDelegate"]
    #[thread_kind = MainThreadOnly]
    #[ivars = ToolbarIvars]
    pub struct ToolbarDelegate;

    unsafe impl NSObjectProtocol for ToolbarDelegate {}

    unsafe impl NSToolbarDelegate for ToolbarDelegate {
        #[unsafe(method_id(toolbar:itemForItemIdentifier:willBeInsertedIntoToolbar:))]
        fn item_for(
            &self,
            _toolbar: &NSToolbar,
            identifier: &NSToolbarItemIdentifier,
            _inserted: bool,
        ) -> Option<Retained<NSToolbarItem>> {
            self.make_item(identifier)
        }

        #[unsafe(method_id(toolbarDefaultItemIdentifiers:))]
        fn default_items(
            &self,
            _toolbar: &NSToolbar,
        ) -> Retained<NSArray<NSToolbarItemIdentifier>> {
            self.identifiers()
        }

        #[unsafe(method_id(toolbarAllowedItemIdentifiers:))]
        fn allowed_items(
            &self,
            _toolbar: &NSToolbar,
        ) -> Retained<NSArray<NSToolbarItemIdentifier>> {
            self.identifiers()
        }
    }
);

impl ToolbarDelegate {
    fn make_item(&self, identifier: &NSToolbarItemIdentifier) -> Option<Retained<NSToolbarItem>> {
        let mtm = MainThreadMarker::from(self);
        let ivars = self.ivars();
        let view: &NSView = match identifier.to_string().as_str() {
            SYSTEM_PROXY => ivars.system_proxy.as_ref(),
            TUN => ivars.tun.as_ref(),
            POLICY => ivars.policy.as_ref(),
            _ => return None,
        };
        let item = NSToolbarItem::initWithItemIdentifier(NSToolbarItem::alloc(mtm), identifier);
        item.setView(Some(view));
        Some(item)
    }

    /// The leading control of the toolbar's trailing group: the traffic
    /// mode, before the capture switches.
    fn first_control(&self) -> &NSView {
        &self.ivars().policy
    }

    /// How far the toolbar's last item, the TUN switch, ends from the
    /// window's edge once AppKit has placed it; the page keeps as much room
    /// on its right, so their edges line up.
    fn end_inset(&self, window: &NSWindow) -> Option<f64> {
        let content = window.contentView()?;
        let tun = &self.ivars().tun;
        let end = tun.convertRect_toView(tun.bounds(), None);
        let inset = content.frame().size.width - (end.origin.x + end.size.width);
        (inset > 0.0 && inset < DRAWER_MARGIN * 4.0).then_some(inset)
    }

    fn identifiers(&self) -> Retained<NSArray<NSToolbarItemIdentifier>> {
        let mut identifiers: Vec<Retained<NSString>> = vec![
            unsafe { NSToolbarFlexibleSpaceItemIdentifier.copy() },
            NSString::from_str(POLICY),
        ];
        if self.ivars().has_system_proxy.get() {
            identifiers.push(NSString::from_str(SYSTEM_PROXY));
        }
        identifiers.push(NSString::from_str(TUN));
        NSArray::from_retained_slice(&identifiers)
    }

    fn new(mtm: MainThreadMarker, post: fn(UiEvent), has_system_proxy: bool) -> Retained<Self> {
        let toggle = |action: ToolbarAction| {
            let button = NSButton::new(mtm);
            button.setButtonType(NSButtonType::PushOnPushOff);
            button.setBezelStyle(NSBezelStyle::Toolbar);
            button.setControlSize(NSControlSize::Small);
            button.setImagePosition(NSCellImagePosition::ImageLeading);
            let target = ActionTarget::new(mtm, move |_| post(UiEvent::Toolbar(action.clone())));
            let object: &AnyObject = target.as_ref();
            unsafe {
                button.setTarget(Some(object));
                button.setAction(Some(ActionTarget::selector()));
            }
            (button, target)
        };
        let (system_proxy, system_proxy_target) = toggle(ToolbarAction::ToggleSystemProxy);
        let (tun, tun_target) = toggle(ToolbarAction::ToggleTun);
        let policy = NSSegmentedControl::new(mtm);
        policy.setTrackingMode(NSSegmentSwitchTracking::SelectOne);
        policy.setControlSize(NSControlSize::Small);
        policy.setSegmentCount(3);
        let policy_target = ActionTarget::new(mtm, move |sender: &AnyObject| {
            let selected: isize = unsafe { msg_send![sender, selectedSegment] };
            if selected >= 0 {
                post(UiEvent::Toolbar(ToolbarAction::Policy(selected as usize)));
            }
        });
        unsafe {
            let object: &AnyObject = policy_target.as_ref();
            policy.setTarget(Some(object));
            policy.setAction(Some(ActionTarget::selector()));
        }
        let this = Self::alloc(mtm).set_ivars(ToolbarIvars {
            system_proxy,
            tun,
            policy,
            has_system_proxy: Cell::new(has_system_proxy),
            _targets: vec![system_proxy_target, tun_target, policy_target],
        });
        unsafe { msg_send![super(this), init] }
    }

    fn update(&self, view: &MainView) {
        let ivars = self.ivars();
        if let Some(toggle) = &view.toolbar.system_proxy {
            style_toggle(&ivars.system_proxy, toggle);
        }
        style_toggle(&ivars.tun, &view.toolbar.tun);
        style_policy(&ivars.policy, &view.toolbar.policy);
    }
}

fn style_toggle(button: &NSButton, toggle: &CaptureToggle) {
    button.setTitle(&NSString::from_str(&toggle.label));
    let color = match (toggle.state, toggle.on) {
        (ToggleState::Pending | ToggleState::Warning, _) => NSColor::systemOrangeColor(),
        (ToggleState::Idle, true) => NSColor::systemGreenColor(),
        (ToggleState::Idle, false) => NSColor::tertiaryLabelColor(),
    };
    button.setImage(style::colored_symbol("circle.fill", &color, 7.0).as_deref());
    button.setState(if toggle.on {
        NSControlStateValueOn
    } else {
        NSControlStateValueOff
    });
    button.setEnabled(toggle.enabled);
    super::hover_help::set(button, toggle.tooltip.as_deref());
}

fn style_policy(control: &NSSegmentedControl, policy: &PolicyControl) {
    for (index, label) in policy.labels.iter().enumerate() {
        control.setLabel_forSegment(&NSString::from_str(label), index as isize);
    }
    control.setSelectedSegment(policy.selected.map(|index| index as isize).unwrap_or(-1));
    control.setEnabled(policy.enabled);
    super::hover_help::set(control, policy.tooltip.as_deref());
}

/// The event monitors that close the open drawer: Esc, and a click outside it.
fn drawer_monitors(
    window: &NSWindow,
    drawer: &NSView,
    post: fn(UiEvent),
) -> Vec<Retained<AnyObject>> {
    [
        escape_monitor(window, post),
        outside_click_monitor(window, drawer, post),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Esc in the main window closes the drawer, unless text is being edited
/// there: Esc then belongs to the text and its input method.
fn escape_monitor(window: &NSWindow, post: fn(UiEvent)) -> Option<Retained<AnyObject>> {
    let number = window.windowNumber();
    let handler = RcBlock::new(move |event: NonNull<NSEvent>| -> *mut NSEvent {
        let key = unsafe { event.as_ref() };
        if key.keyCode() == ESCAPE && key.windowNumber() == number && !editing_text(key) {
            post(UiEvent::CloseDrawer);
            return std::ptr::null_mut();
        }
        event.as_ptr()
    });
    unsafe { NSEvent::addLocalMonitorForEventsMatchingMask_handler(NSEventMask::KeyDown, &handler) }
}

/// A click in the window's content outside the drawer, on the page or the
/// sidebar, closes it and still reaches what it hit; the toolbar's controls,
/// the message button among them, leave the drawer to themselves.
fn outside_click_monitor(
    window: &NSWindow,
    drawer: &NSView,
    post: fn(UiEvent),
) -> Option<Retained<AnyObject>> {
    let number = window.windowNumber();
    let drawer = drawer.retain();
    let handler = RcBlock::new(move |event: NonNull<NSEvent>| -> *mut NSEvent {
        let click = unsafe { event.as_ref() };
        let point = click.locationInWindow();
        let in_content = MainThreadMarker::new()
            .and_then(|mtm| click.window(mtm))
            .is_some_and(|window| NSPointInRect(point, window.contentLayoutRect()));
        let in_drawer =
            drawer.mouse_inRect(drawer.convertPoint_fromView(point, None), drawer.bounds());
        if click.windowNumber() == number && in_content && !in_drawer {
            post(UiEvent::CloseDrawer);
        }
        event.as_ptr()
    });
    unsafe {
        NSEvent::addLocalMonitorForEventsMatchingMask_handler(
            NSEventMask::LeftMouseDown | NSEventMask::RightMouseDown,
            &handler,
        )
    }
}

fn editing_text(event: &NSEvent) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        return false;
    };
    event
        .window(mtm)
        .and_then(|window| window.firstResponder())
        .is_some_and(|responder| responder.isKindOfClass(NSTextView::class()))
}

/// A pane that shows the desktop through the window, like the sidebar: the
/// material the window's background uses, always active.
fn translucent_pane(mtm: MainThreadMarker) -> Retained<NSView> {
    let pane = NSVisualEffectView::new(mtm);
    pane.setMaterial(NSVisualEffectMaterial::UnderWindowBackground);
    pane.setBlendingMode(NSVisualEffectBlendingMode::BehindWindow);
    pane.setState(NSVisualEffectState::Active);
    super::widgets::pin(&Wash::view(mtm), &pane, 0.0);
    Retained::into_super(pane)
}

define_class!(
    /// A light wash over the window's material, so the background stays
    /// bright and lets the desktop through.
    #[unsafe(super(NSView))]
    #[name = "EgrioWash"]
    #[thread_kind = MainThreadOnly]
    pub struct Wash;

    impl Wash {
        #[unsafe(method(drawRect:))]
        fn draw_rect(&self, dirty: NSRect) {
            let names = unsafe {
                NSArray::from_slice(&[NSAppearanceNameAqua, NSAppearanceNameDarkAqua])
            };
            let dark = self
                .effectiveAppearance()
                .bestMatchFromAppearancesWithNames(&names)
                .is_some_and(|name| unsafe { &*name == NSAppearanceNameDarkAqua });
            let color = if dark {
                NSColor::colorWithSRGBRed_green_blue_alpha(28.0 / 255.0, 28.0 / 255.0, 30.0 / 255.0, 0.56)
            } else {
                NSColor::colorWithSRGBRed_green_blue_alpha(250.0 / 255.0, 250.0 / 255.0, 253.0 / 255.0, 0.48)
            };
            color.setFill();
            objc2_app_kit::NSRectFillUsingOperation(dirty, objc2_app_kit::NSCompositingOperation::SourceOver);
        }
    }
);

impl Wash {
    fn view(mtm: MainThreadMarker) -> Retained<NSView> {
        let this: Retained<Self> = unsafe { msg_send![Self::alloc(mtm), init] };
        Retained::into_super(this)
    }
}

define_class!(
    /// A split view whose dividers draw nothing.
    #[unsafe(super(NSSplitView))]
    #[name = "EgrioQuietSplitView"]
    #[thread_kind = MainThreadOnly]
    pub struct QuietSplitView;

    impl QuietSplitView {
        #[unsafe(method_id(dividerColor))]
        fn divider_color(&self) -> Retained<NSColor> {
            NSColor::clearColor()
        }

        #[unsafe(method(dividerThickness))]
        fn divider_thickness(&self) -> f64 {
            0.0
        }
    }
);

impl QuietSplitView {
    fn view(mtm: MainThreadMarker) -> Retained<NSSplitView> {
        let this = Self::alloc(mtm);
        let this: Retained<Self> = unsafe { msg_send![this, init] };
        // Panes side by side, as the split view controller's own split view has them.
        this.setVertical(true);
        this.setDividerStyle(NSSplitViewDividerStyle::Thin);
        Retained::into_super(this)
    }
}

define_class!(
    /// The window's split view controller, whose divider stays put: clicks
    /// never start dragging it, as the divider's effective rect is where
    /// they would (`NSSplitView.h`), so it shows no resize cursor either.
    #[unsafe(super(NSSplitViewController, NSViewController, NSResponder, NSObject))]
    #[name = "EgrioFixedSplitViewController"]
    #[thread_kind = MainThreadOnly]
    pub struct FixedSplitViewController;

    impl FixedSplitViewController {
        #[unsafe(method(splitView:effectiveRect:forDrawnRect:ofDividerAtIndex:))]
        fn effective_rect(
            &self,
            split: &NSSplitView,
            proposed: NSRect,
            drawn: NSRect,
            index: NSInteger,
        ) -> NSRect {
            // The controller's own implementation must run (NS_REQUIRES_SUPER).
            let _: NSRect = unsafe {
                msg_send![
                    super(self),
                    splitView: split,
                    effectiveRect: proposed,
                    forDrawnRect: drawn,
                    ofDividerAtIndex: index
                ]
            };
            NSRect::ZERO
        }

        #[unsafe(method(splitView:additionalEffectiveRectOfDividerAtIndex:))]
        fn additional_effective_rect(&self, split: &NSSplitView, index: NSInteger) -> NSRect {
            let _: NSRect = unsafe {
                msg_send![
                    super(self),
                    splitView: split,
                    additionalEffectiveRectOfDividerAtIndex: index
                ]
            };
            NSRect::ZERO
        }
    }
);

impl FixedSplitViewController {
    fn controller(mtm: MainThreadMarker) -> Retained<NSSplitViewController> {
        let this: Retained<Self> = unsafe { msg_send![Self::alloc(mtm), init] };
        Retained::into_super(this)
    }
}

/// Puts the message capsule in the title bar's view, at the start of the
/// band the title bar leaves over the page pane, in line with the page and
/// centered in the band; the window's frame view, which holds both views,
/// holds the constraints between them.
fn place_capsule(window: &NSWindow, capsule: &NSView, pane: &NSView) {
    let Some(bar) = window
        .standardWindowButton(objc2_app_kit::NSWindowButton::CloseButton)
        .and_then(|button| unsafe { button.superview() })
    else {
        log::warn!("no title bar view for the message capsule");
        return;
    };
    bar.addSubview(capsule);
    let band = objc2_app_kit::NSLayoutGuide::new();
    pane.addLayoutGuide(&band);
    NSLayoutConstraint::activateConstraints(&NSArray::from_retained_slice(&[
        band.topAnchor().constraintEqualToAnchor(&pane.topAnchor()),
        band.bottomAnchor()
            .constraintEqualToAnchor(&pane.safeAreaLayoutGuide().topAnchor()),
        capsule
            .leadingAnchor()
            .constraintEqualToAnchor_constant(&pane.leadingAnchor(), PAGE_LEADING),
        capsule
            .centerYAnchor()
            .constraintEqualToAnchor(&band.centerYAnchor()),
    ]));
}

pub struct MainWindow {
    window: Retained<NSWindow>,
    /// The message capsule, whose surface is the message panel.
    capsule: Retained<super::messages::MessageCapsule>,
    /// What closes the drawer while it is open.
    drawer_monitors: Vec<Retained<AnyObject>>,
    post: fn(UiEvent),
    sidebar_table: Retained<NSTableView>,
    sidebar: Retained<SidebarController>,
    toolbar: Retained<ToolbarDelegate>,
    _delegate: Retained<WindowDelegate>,
    _split: Retained<NSSplitViewController>,
    pub content: Surface,
    pub drawer: Surface,
    /// The open dialog, a sheet over the window.
    pub dialog: Option<Dialog>,
    view: MainView,
}

impl MainWindow {
    pub fn open(
        mtm: MainThreadMarker,
        view: &MainView,
        content: &Mounted,
        drawer: &Mounted,
        post: fn(UiEvent),
    ) -> Self {
        let style = NSWindowStyleMask::Titled
            | NSWindowStyleMask::Closable
            | NSWindowStyleMask::Miniaturizable
            | NSWindowStyleMask::Resizable
            | NSWindowStyleMask::FullSizeContentView;
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                NSWindow::alloc(mtm),
                NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(1120.0, 720.0)),
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        unsafe { window.setReleasedWhenClosed(false) };
        window.setContentMinSize(NSSize::new(980.0, 640.0));
        window.setTitle(&NSString::from_str(&view.title));

        let delegate = WindowDelegate::alloc(mtm).set_ivars(WindowIvars {
            post,
            resized: RefCell::new(None),
        });
        let delegate: Retained<WindowDelegate> = unsafe { msg_send![super(delegate), init] };
        window.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));

        // Sidebar: the sections as a source list.
        let sidebar = SidebarController::alloc(mtm).set_ivars(SidebarIvars {
            items: RefCell::new(view.nav.clone()),
            post,
            quiet: Cell::new(true),
        });
        let sidebar: Retained<SidebarController> = unsafe { msg_send![super(sidebar), init] };
        let sidebar_table = NSTableView::new(mtm);
        sidebar_table.setStyle(NSTableViewStyle::SourceList);
        sidebar_table.setHeaderView(None);
        sidebar_table.setRowHeight(28.0);
        let column = NSTableColumn::initWithIdentifier(
            NSTableColumn::alloc(mtm),
            &NSString::from_str("section"),
        );
        column.setResizingMask(objc2_app_kit::NSTableColumnResizingOptions::AutoresizingMask);
        sidebar_table.addTableColumn(&column);
        sidebar_table.setColumnAutoresizingStyle(
            objc2_app_kit::NSTableViewColumnAutoresizingStyle::FirstColumnOnlyAutoresizingStyle,
        );
        unsafe {
            sidebar_table.setDataSource(Some(ProtocolObject::from_ref(&*sidebar)));
            sidebar_table.setDelegate(Some(ProtocolObject::from_ref(&*sidebar)));
        }
        let sidebar_scroll = NSScrollView::new(mtm);
        sidebar_scroll.setDocumentView(Some(&sidebar_table));
        sidebar_scroll.setDrawsBackground(false);
        // A plain pane on the window's one background, not a sidebar item
        // with a material of its own.
        let sidebar_pane = translucent_pane(mtm);
        super::widgets::pin(&sidebar_scroll, &sidebar_pane, 0.0);
        let sidebar_controller = NSViewController::new(mtm);
        sidebar_controller.setView(&sidebar_pane);
        let sidebar_item = NSSplitViewItem::splitViewItemWithViewController(&sidebar_controller);
        sidebar_item.setMinimumThickness(SIDEBAR_WIDTH);
        sidebar_item.setMaximumThickness(SIDEBAR_WIDTH);
        sidebar_item.setCanCollapse(false);

        let content_host = translucent_pane(mtm);
        // The page in its own view, under the panel that floats over it.
        let page_host = NSView::new(mtm);
        super::widgets::pin(&page_host, &content_host, 0.0);
        let content_controller = NSViewController::new(mtm);
        content_controller.setView(&content_host);
        let content_item = NSSplitViewItem::splitViewItemWithViewController(&content_controller);
        content_item.setMinimumThickness(PAGE_MIN_WIDTH);

        let split = FixedSplitViewController::controller(mtm);
        // The panes sit on one translucent background, with no line between them.
        split.setSplitView(&QuietSplitView::view(mtm));
        split.addSplitViewItem(&sidebar_item);
        split.addSplitViewItem(&content_item);
        window.setContentViewController(Some(&split));
        // A content view controller sizes the window to its views; give it
        // the default size back before restoring the user's frame.
        window.setContentSize(NSSize::new(1120.0, 720.0));

        let toolbar_delegate = ToolbarDelegate::new(mtm, post, view.toolbar.system_proxy.is_some());
        let toolbar =
            NSToolbar::initWithIdentifier(NSToolbar::alloc(mtm), &NSString::from_str("EgrioMain"));
        toolbar.setDisplayMode(NSToolbarDisplayMode::IconOnly);
        toolbar.setAllowsUserCustomization(false);
        toolbar.setDelegate(Some(ProtocolObject::from_ref(&*toolbar_delegate)));
        window.setToolbar(Some(&toolbar));
        // The compact toolbar keeps the controls at a title bar's size.
        window.setToolbarStyle(NSWindowToolbarStyle::UnifiedCompact);
        window.setTitlebarSeparatorStyle(NSTitlebarSeparatorStyle::None);
        // The panes' background runs up under the toolbar: one background for
        // the whole window.
        window.setTitlebarAppearsTransparent(true);
        window.setTitleVisibility(NSWindowTitleVisibility::Hidden);
        toolbar_delegate.update(view);
        // The capsule starts the band over the page and never grows into the
        // switches, and its surface, the panel, lies over the page; both
        // follow the window's size.
        let capsule = super::messages::MessageCapsule::new(mtm, post);
        capsule.update(&view.toolbar.messages);
        place_capsule(&window, &capsule, &content_host);
        capsule.keep_before(toolbar_delegate.first_control());
        // The panel lies over the whole window's content rather than in the
        // page's pane, whose split view item clips it: its shadow falls on
        // the sidebar too.
        if let Some(over) = window.contentView() {
            capsule.hang(&over, &content_host, DRAWER_MARGIN);
        }
        {
            let capsule = capsule.clone();
            *delegate.ivars().resized.borrow_mut() = Some(Box::new(move || capsule.fit()));
        }

        // The page's right edge lines up with the toolbar's.
        window.layoutIfNeeded();
        let page_insets = NSEdgeInsets {
            right: toolbar_delegate
                .end_inset(&window)
                .unwrap_or(PAGE_INSETS.right),
            ..PAGE_INSETS
        };
        let mut content_surface = Surface::new(mtm, page_host, post);
        content_surface.set_root(content, page_insets);
        let mut drawer_surface = Surface::new(mtm, capsule.body().retain(), post);
        // Under the title bar, which the body's safe area keeps it from.
        drawer_surface.set_root(
            drawer,
            NSEdgeInsets {
                top: DRAWER_GAP,
                left: DRAWER_INSET,
                bottom: DRAWER_INSET,
                right: DRAWER_INSET,
            },
        );

        // The frame the user left the window in, or centered the first time.
        let restored = window.setFrameUsingName(&NSString::from_str("EgrioMain"));
        if !restored {
            window.center();
        }
        window.setFrameAutosaveName(&NSString::from_str("EgrioMain"));

        let drawer_monitors = if view.drawer_open {
            self::drawer_monitors(&window, capsule.panel(), post)
        } else {
            Vec::new()
        };
        let this = Self {
            window,
            capsule,
            drawer_monitors,
            post,
            sidebar_table,
            sidebar,
            toolbar: toolbar_delegate,
            _delegate: delegate,
            _split: split,
            content: content_surface,
            drawer: drawer_surface,
            dialog: None,
            view: view.clone(),
        };
        this.sidebar_table.reloadData();
        this.select_section(view);
        this.sidebar.ivars().quiet.set(false);
        this.window.makeKeyAndOrderFront(None);
        log::debug!("main window number {}", this.window.windowNumber());
        this
    }

    fn select_section(&self, view: &MainView) {
        let Some(row) = view
            .nav
            .iter()
            .position(|item| item.section == view.section)
        else {
            return;
        };
        let quiet = self.sidebar.ivars().quiet.replace(true);
        let indexes = objc2_foundation::NSIndexSet::indexSetWithIndex(row);
        self.sidebar_table
            .selectRowIndexes_byExtendingSelection(&indexes, false);
        self.sidebar.ivars().quiet.set(quiet);
    }

    pub fn update(&mut self, view: &MainView) {
        // The window's own title stays hidden; the Window menu and Mission
        // Control show it.
        if view.title != self.view.title {
            self.window.setTitle(&NSString::from_str(&view.title));
        }
        if view.toolbar.messages != self.view.toolbar.messages {
            self.capsule.update(&view.toolbar.messages);
        }
        if view.nav != self.view.nav {
            *self.sidebar.ivars().items.borrow_mut() = view.nav.clone();
            let quiet = self.sidebar.ivars().quiet.replace(true);
            self.sidebar_table.reloadData();
            self.sidebar.ivars().quiet.set(quiet);
        }
        if view.section != self.view.section || view.nav != self.view.nav {
            self.select_section(view);
        }
        if view.toolbar != self.view.toolbar {
            self.toolbar.update(view);
        }
        if view.drawer_open != self.view.drawer_open {
            self.remove_drawer_monitors();
            if view.drawer_open {
                self.release_page_focus();
                self.drawer_monitors =
                    drawer_monitors(&self.window, self.capsule.panel(), self.post);
            }
        }
        self.view = view.clone();
    }

    /// The toolbar's controls and the pages' show the interface's values
    /// again after the user moved one.
    pub fn settle(&self) {
        self.toolbar.update(&self.view);
        self.content.settle();
        self.drawer.settle();
        if let Some(dialog) = self.dialog.as_ref() {
            dialog.surface.settle();
        }
    }

    pub fn open_dialog(&mut self, mtm: MainThreadMarker, tree: &Mounted, post: fn(UiEvent)) {
        self.close_dialog();
        self.dialog = Some(Dialog::open(mtm, &self.window, tree, post));
    }

    pub fn close_dialog(&mut self) {
        if let Some(dialog) = self.dialog.take() {
            dialog.close(&self.window);
        }
    }

    /// The window a panel opens over: the dialog when one is open.
    pub fn sheet_parent(&self) -> &NSWindow {
        match self.dialog.as_ref() {
            Some(dialog) => dialog.window(),
            None => &self.window,
        }
    }

    pub fn bring_to_front(&self) {
        self.window.makeKeyAndOrderFront(None);
    }

    pub fn window(&self) -> &NSWindow {
        &self.window
    }

    pub fn close(&self) {
        if self.window.isVisible() {
            self.window.close();
        }
    }

    /// Takes the keyboard from the page when the drawer opens over it: a
    /// control there would take keys out of sight, and AppKit draws its
    /// focus ring over the drawer.
    fn release_page_focus(&self) {
        let in_page = self
            .window
            .firstResponder()
            .and_then(|responder| responder.downcast::<NSView>().ok())
            .is_some_and(|view| view.isDescendantOf(self.content.host()));
        if in_page {
            self.window.makeFirstResponder(None);
        }
    }

    fn remove_drawer_monitors(&mut self) {
        for monitor in self.drawer_monitors.drain(..) {
            unsafe { NSEvent::removeMonitor(&monitor) };
        }
    }
}

impl Drop for MainWindow {
    fn drop(&mut self) {
        self.remove_drawer_monitors();
    }
}
