//! Text the user edits: fields that report each edit, search fields, and
//! names edited in place. A field's value is written back only when the
//! interface's value differs from the one the field last reported, so an
//! input method's composition (marked text) is never replaced while the user
//! types.

use std::cell::{Cell, RefCell};

use objc2::rc::Retained;
use objc2::runtime::{Bool, NSObjectProtocol, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSControl, NSControlTextEditingDelegate, NSLayoutPriorityDefaultLow, NSSearchField,
    NSSearchFieldDelegate, NSTextField, NSTextFieldDelegate, NSTextView,
};
use objc2_foundation::{NSNotification, NSObject, NSString};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{EditableText, TextField};
use egrio_ui::reconcile::NodeId;

use super::style;

/// A search field's width while its row has room, and the least it gives way
/// to when the row is tight.
const SEARCH_WIDTH: f64 = 240.0;
const SEARCH_MIN_WIDTH: f64 = 140.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Reports every edit.
    Field,
    /// Commits the edited text when editing ends, or goes back on Esc.
    Editable,
}

pub struct TextIvars {
    post: fn(UiEvent),
    id: NodeId,
    role: Role,
    /// The field's value as last reported, or the editable text's value
    /// before editing.
    known: RefCell<String>,
    /// Esc ended this edit.
    cancelled: Cell<bool>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioTextDelegate"]
    #[thread_kind = MainThreadOnly]
    #[ivars = TextIvars]
    pub struct TextDelegate;

    unsafe impl NSObjectProtocol for TextDelegate {}

    unsafe impl NSControlTextEditingDelegate for TextDelegate {
        #[unsafe(method(controlTextDidChange:))]
        fn did_change(&self, notification: &NSNotification) {
            let ivars = self.ivars();
            if ivars.role != Role::Field {
                return;
            }
            if let Some(field) = control(notification) {
                self.report(&field);
            }
        }

        #[unsafe(method(controlTextDidBeginEditing:))]
        fn did_begin(&self, _notification: &NSNotification) {
            self.ivars().cancelled.set(false);
        }

        #[unsafe(method(controlTextDidEndEditing:))]
        fn did_end(&self, notification: &NSNotification) {
            let ivars = self.ivars();
            if ivars.role != Role::Editable {
                return;
            }
            let Some(field) = control(notification) else {
                return;
            };
            let original = ivars.known.borrow().clone();
            let edited = field.stringValue().to_string();
            let changed = !edited.trim().is_empty() && edited.trim() != original;
            // The text shows the interface's name until the interface has the new one.
            field.setStringValue(&NSString::from_str(&original));
            if changed && !ivars.cancelled.get() {
                (ivars.post)(UiEvent::Node {
                    id: ivars.id,
                    event: Event::Commit(edited.trim().to_string()),
                });
            }
        }

        #[unsafe(method(control:textView:doCommandBySelector:))]
        fn do_command(&self, control: &NSControl, _text_view: &NSTextView, command: Sel) -> Bool {
            if self.ivars().role != Role::Editable {
                return Bool::NO;
            }
            if command == sel!(cancelOperation:) {
                self.ivars().cancelled.set(true);
                end_editing(control);
                return Bool::YES;
            }
            if command == sel!(insertNewline:) {
                end_editing(control);
                return Bool::YES;
            }
            Bool::NO
        }
    }

    unsafe impl NSTextFieldDelegate for TextDelegate {}

    unsafe impl NSSearchFieldDelegate for TextDelegate {}

    impl TextDelegate {
        /// A search field's action: its cancel button cleared it.
        #[unsafe(method(searched:))]
        fn searched(&self, field: &NSTextField) {
            self.report(field);
        }
    }
);

fn control(notification: &NSNotification) -> Option<Retained<NSTextField>> {
    notification.object()?.downcast::<NSTextField>().ok()
}

/// Gives up the keyboard, which ends the edit.
fn end_editing(control: &NSControl) {
    if let Some(window) = control.window() {
        window.makeFirstResponder(None);
    }
}

impl TextDelegate {
    /// Reports the field's value when it is not the one last reported.
    fn report(&self, field: &NSTextField) {
        let ivars = self.ivars();
        let value = field.stringValue().to_string();
        if *ivars.known.borrow() == value {
            return;
        }
        *ivars.known.borrow_mut() = value.clone();
        (ivars.post)(UiEvent::Node {
            id: ivars.id,
            event: Event::Changed(value),
        });
    }

    fn new(
        mtm: MainThreadMarker,
        post: fn(UiEvent),
        id: NodeId,
        role: Role,
        known: String,
    ) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(TextIvars {
            post,
            id,
            role,
            known: RefCell::new(known),
            cancelled: Cell::new(false),
        });
        unsafe { msg_send![super(this), init] }
    }
}

pub fn text_field(
    mtm: MainThreadMarker,
    props: &TextField,
    post: fn(UiEvent),
    id: NodeId,
) -> (Retained<NSTextField>, Retained<TextDelegate>) {
    let field = NSTextField::new(mtm);
    field.setEditable(true);
    field.setSelectable(true);
    field.setBezeled(true);
    field.setUsesSingleLineMode(true);
    field.setFont(Some(&style::font(egrio_ui::node::TextStyle::Body)));
    let delegate = TextDelegate::new(mtm, post, id, Role::Field, String::new());
    // The delegate is weak; the realized node keeps it alive.
    unsafe { field.setDelegate(Some(ProtocolObject::from_ref(&*delegate))) };
    style_text_field(&field, &delegate, props);
    (field, delegate)
}

pub fn search_field(
    mtm: MainThreadMarker,
    props: &TextField,
    post: fn(UiEvent),
    id: NodeId,
) -> (Retained<NSTextField>, Retained<TextDelegate>) {
    let field = NSSearchField::new(mtm);
    let delegate = TextDelegate::new(mtm, post, id, Role::Field, String::new());
    // The delegate and the target are weak; the realized node keeps it alive.
    unsafe {
        field.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
        field.setTarget(Some(&delegate));
        field.setAction(Some(sel!(searched:)));
    }
    let preferred = field.widthAnchor().constraintEqualToConstant(SEARCH_WIDTH);
    preferred.setPriority(NSLayoutPriorityDefaultLow);
    preferred.setActive(true);
    field
        .widthAnchor()
        .constraintGreaterThanOrEqualToConstant(SEARCH_MIN_WIDTH)
        .setActive(true);
    let field = Retained::into_super(field);
    style_text_field(&field, &delegate, props);
    (field, delegate)
}

pub fn style_text_field(field: &NSTextField, delegate: &TextDelegate, props: &TextField) {
    let known = &delegate.ivars().known;
    if *known.borrow() != props.value {
        field.setStringValue(&NSString::from_str(&props.value));
        *known.borrow_mut() = props.value.clone();
    }
    field.setPlaceholderString(Some(&NSString::from_str(&props.placeholder)));
    field.setEnabled(props.enabled && props.on_change.is_some());
}

pub fn editable_text(
    mtm: MainThreadMarker,
    props: &EditableText,
    post: fn(UiEvent),
    id: NodeId,
) -> (Retained<NSTextField>, Retained<TextDelegate>) {
    let field = NSTextField::new(mtm);
    field.setBezeled(false);
    field.setBordered(false);
    field.setDrawsBackground(false);
    field.setUsesSingleLineMode(true);
    field.setLineBreakMode(objc2_app_kit::NSLineBreakMode::ByTruncatingTail);
    field.setContentCompressionResistancePriority_forOrientation(
        super::widgets::TEXT_COMPRESSION,
        objc2_app_kit::NSLayoutConstraintOrientation::Horizontal,
    );
    let delegate = TextDelegate::new(mtm, post, id, Role::Editable, props.text.clone());
    // The delegate is weak; the realized node keeps it alive.
    unsafe { field.setDelegate(Some(ProtocolObject::from_ref(&*delegate))) };
    field.setStringValue(&NSString::from_str(&props.text));
    style_editable(&field, &delegate, props);
    (field, delegate)
}

pub fn style_editable(field: &NSTextField, delegate: &TextDelegate, props: &EditableText) {
    field.setFont(Some(&style::font(props.style)));
    // While the user edits, the edit stays; the new name arrives after it.
    if field.currentEditor().is_none() {
        field.setStringValue(&NSString::from_str(&props.text));
        *delegate.ivars().known.borrow_mut() = props.text.clone();
    }
    let enabled = props.enabled && props.on_commit.is_some();
    field.setEditable(enabled);
    field.setSelectable(enabled);
}
