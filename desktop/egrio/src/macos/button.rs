//! Buttons: push, plain and icon-only. A busy button keeps its size and
//! shows a spinner where its icon is, or over its label when it has none;
//! the icon or label stays laid out, drawn clear.

use std::cell::RefCell;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObjectProtocol};
use objc2::{define_class, msg_send, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSBezelStyle, NSButton, NSCellImagePosition, NSColor, NSControlSize, NSFontAttributeName,
    NSForegroundColorAttributeName, NSProgressIndicator, NSProgressIndicatorStyle,
};
use objc2_foundation::{
    NSAttributedString, NSAttributedStringKey, NSDictionary, NSPoint, NSRect, NSSize, NSString,
};

use egrio_ui::node::{Button, ButtonKey, ButtonStyle, Tone};

use super::style;
use super::target::ActionTarget;

const SPINNER: f64 = 16.0;

pub struct ButtonIvars {
    /// Shown while the button is busy.
    spinner: RefCell<Option<Retained<NSProgressIndicator>>>,
}

define_class!(
    #[unsafe(super(NSButton))]
    #[name = "EgrioButton"]
    #[thread_kind = MainThreadOnly]
    #[ivars = ButtonIvars]
    pub struct EgrioButton;

    unsafe impl NSObjectProtocol for EgrioButton {}

    impl EgrioButton {
        #[unsafe(method(layout))]
        fn layout(&self) {
            let _: () = unsafe { msg_send![super(self), layout] };
            self.place_spinner();
        }

        #[unsafe(method(setFrameSize:))]
        fn set_frame_size(&self, size: NSSize) {
            let _: () = unsafe { msg_send![super(self), setFrameSize: size] };
            self.place_spinner();
        }
    }
);

impl EgrioButton {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(ButtonIvars {
            spinner: RefCell::new(None),
        });
        unsafe { msg_send![super(this), init] }
    }

    /// Centers the spinner where the icon is drawn, or on the button.
    fn place_spinner(&self) {
        let Some(spinner) = self.ivars().spinner.borrow().clone() else {
            return;
        };
        let bounds = self.bounds();
        let around = match self.cell() {
            Some(cell) if self.imagePosition() != NSCellImagePosition::NoImage => {
                cell.imageRectForBounds(bounds)
            }
            _ => bounds,
        };
        let center = NSPoint::new(
            around.origin.x + around.size.width / 2.0,
            around.origin.y + around.size.height / 2.0,
        );
        spinner.setFrame(NSRect::new(
            NSPoint::new(center.x - SPINNER / 2.0, center.y - SPINNER / 2.0),
            NSSize::new(SPINNER, SPINNER),
        ));
    }

    fn show_busy(&self, busy: bool) {
        let mut spinner = self.ivars().spinner.borrow_mut();
        match (busy, spinner.as_ref()) {
            (true, None) => {
                let view = NSProgressIndicator::new(MainThreadMarker::from(self));
                view.setStyle(NSProgressIndicatorStyle::Spinning);
                view.setControlSize(NSControlSize::Small);
                view.setIndeterminate(true);
                self.addSubview(&view);
                unsafe { view.startAnimation(None) };
                *spinner = Some(view);
            }
            (false, Some(view)) => {
                unsafe { view.stopAnimation(None) };
                view.removeFromSuperview();
                *spinner = None;
            }
            _ => {}
        }
        drop(spinner);
        self.place_spinner();
    }
}

pub fn button_view(
    mtm: MainThreadMarker,
    props: &Button,
    target: &ActionTarget,
) -> Retained<NSButton> {
    let button = EgrioButton::new(mtm);
    let target: &AnyObject = target.as_ref();
    unsafe {
        button.setTarget(Some(target));
        button.setAction(Some(ActionTarget::selector()));
    }
    let button = Retained::into_super(button);
    style_button(&button, props);
    button
}

/// The label drawn clear, so it keeps its place under the spinner.
fn clear_title(button: &NSButton, label: &str) -> Retained<NSAttributedString> {
    let string = NSString::from_str(label);
    let Some(font) = button.font() else {
        return NSAttributedString::from_nsstring(&string);
    };
    let color = NSColor::clearColor();
    let keys: [&NSAttributedStringKey; 2] =
        unsafe { [NSFontAttributeName, NSForegroundColorAttributeName] };
    let values: [&AnyObject; 2] = [font.as_ref(), color.as_ref()];
    let attributes = NSDictionary::from_slices(&keys, &values);
    unsafe { NSAttributedString::new_with_attributes(&string, &attributes) }
}

pub fn style_button(button: &NSButton, props: &Button) {
    let label = props.label.as_deref().unwrap_or("");
    let busy = props.busy;
    match props.icon {
        Some(icon) => {
            // A busy button's icon is drawn clear where the spinner turns.
            let image = if busy {
                style::clear_symbol(icon)
            } else {
                style::symbol(icon)
            };
            button.setImage(image.as_deref());
            button.setImagePosition(if props.label.is_some() {
                NSCellImagePosition::ImageLeading
            } else {
                NSCellImagePosition::ImageOnly
            });
            button.setTitle(&NSString::from_str(label));
        }
        None => {
            button.setImage(None);
            button.setImagePosition(NSCellImagePosition::NoImage);
            if busy && !label.is_empty() {
                button.setAttributedTitle(&clear_title(button, label));
            } else {
                button.setTitle(&NSString::from_str(label));
            }
        }
    }
    let tint = (props.tone != Tone::Default).then(|| style::color(props.tone));
    button.setContentTintColor(tint.as_deref());
    // In a dialog, Return presses the default button and Esc the cancel one.
    button.setKeyEquivalent(&NSString::from_str(match props.key {
        Some(ButtonKey::Return) => "\r",
        Some(ButtonKey::Escape) => "\u{1b}",
        None => "",
    }));
    match props.style {
        ButtonStyle::Primary | ButtonStyle::Secondary | ButtonStyle::Destructive => {
            button.setBordered(true);
            button.setBezelStyle(NSBezelStyle::Push);
            // A reused plain button showed its bezel only under the pointer.
            button.setShowsBorderOnlyWhileMouseInside(false);
            button.setBezelColor(
                match props.style {
                    ButtonStyle::Primary => Some(NSColor::controlAccentColor()),
                    ButtonStyle::Destructive => Some(NSColor::systemRedColor()),
                    _ => None,
                }
                .as_deref(),
            );
        }
        ButtonStyle::Plain => {
            // The accessory bar bezel, shown while the pointer is over it.
            button.setBordered(true);
            button.setBezelStyle(NSBezelStyle::AccessoryBar);
            button.setShowsBorderOnlyWhileMouseInside(true);
            button.setBezelColor(None);
        }
    }
    button.setEnabled(props.enabled && !busy && props.on_press.is_some());
    if let Some(button) = button.downcast_ref::<EgrioButton>() {
        button.show_busy(busy);
    }
}
