//! The popover component: a plain button that shows a transient `NSPopover`
//! below it, the node's child as the content. AppKit closes the popover when
//! the user works outside it or presses Esc; whether it is open stays here.
//! The content is realized and patched like any tree, also while the
//! popover is closed, and the popover takes the content's size when it opens
//! and whenever the content changes.

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::MainThreadMarker;
use objc2_app_kit::{
    NSButton, NSPopover, NSPopoverBehavior, NSResponder, NSTextField, NSView, NSViewController,
};
use objc2_foundation::NSRectEdge;

use egrio_ui::node::{Button, ButtonStyle, Popover, Tone};

use super::button::{button_view, style_button};
use super::target::ActionTarget;

/// The space between the popover's edge and its content.
pub const INSET: f64 = 14.0;
/// What test control knows a popover's content by.
#[cfg(feature = "test-control")]
pub const IDENTIFIER: &str = "egrio.popover";

pub struct PopoverParts {
    pub button: Retained<NSButton>,
    popover: Retained<NSPopover>,
    /// The content's view, which the node's child fills.
    pub host: Retained<NSView>,
    _controller: Retained<NSViewController>,
    _target: Retained<ActionTarget>,
}

/// The popover's button looks like a plain button. Its press shows the
/// popover rather than reaching the interface, so it has no handler and
/// takes its enabled state from the popover.
fn look(props: &Popover) -> Button {
    Button {
        label: Some(props.label.clone()),
        icon: props.icon,
        tone: Tone::Default,
        style: ButtonStyle::Plain,
        key: None,
        enabled: props.enabled,
        busy: false,
        on_press: None,
    }
}

impl PopoverParts {
    pub fn new(mtm: MainThreadMarker, props: &Popover) -> Self {
        let host = NSView::new(mtm);
        #[cfg(feature = "test-control")]
        {
            use objc2_app_kit::NSUserInterfaceItemIdentification;
            host.setIdentifier(Some(&objc2_foundation::NSString::from_str(IDENTIFIER)));
        }
        let controller = NSViewController::new(mtm);
        controller.setView(&host);
        let popover = NSPopover::new(mtm);
        popover.setContentViewController(Some(&controller));
        popover.setBehavior(NSPopoverBehavior::Transient);
        popover.setAnimates(true);
        let shown = popover.clone();
        let content = host.clone();
        let target = ActionTarget::new(mtm, move |sender: &AnyObject| {
            if shown.isShown() {
                shown.close();
                return;
            }
            let Some(anchor) = sender.downcast_ref::<NSView>() else {
                return;
            };
            fit(&shown, &content);
            // Below the button, whichever way its coordinates run.
            let below = if anchor.isFlipped() {
                NSRectEdge::MaxY
            } else {
                NSRectEdge::MinY
            };
            shown.showRelativeToRect_ofView_preferredEdge(anchor.bounds(), anchor, below);
            focus_first_field(&content);
        });
        let button = button_view(mtm, &look(props), &target);
        button.setEnabled(props.enabled);
        Self {
            button,
            popover,
            host,
            _controller: controller,
            _target: target,
        }
    }

    pub fn update(&self, props: &Popover) {
        style_button(&self.button, &look(props));
        self.button.setEnabled(props.enabled);
        if !props.enabled && self.popover.isShown() {
            self.popover.close();
        }
    }

    /// Takes the content's new size while the popover shows.
    pub fn refit(&self) {
        if self.popover.isShown() {
            fit(&self.popover, &self.host);
        }
    }
}

fn fit(popover: &NSPopover, content: &NSView) {
    content.layoutSubtreeIfNeeded();
    popover.setContentSize(content.fittingSize());
}

/// Puts the keyboard in the content's first editable field, as a panel that
/// asks for something does.
fn focus_first_field(view: &NSView) {
    fn first(view: &NSView) -> Option<Retained<NSTextField>> {
        if let Some(field) = view.downcast_ref::<NSTextField>() {
            if field.isEditable() {
                return Some(objc2::Message::retain(field));
            }
        }
        view.subviews().iter().find_map(|child| first(&child))
    }
    if let (Some(field), Some(window)) = (first(view), view.window()) {
        let responder: &NSResponder = &field;
        window.makeFirstResponder(Some(responder));
    }
}
