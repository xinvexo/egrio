//! The plain text editor: an `NSTextView` in its scroll view, monospaced,
//! with every automatic substitution and check off, so the text is exactly
//! what the user typed. Like a text field it reports each edit, and the
//! interface's text is written back only when it differs from the one last
//! reported, so an input method's composition is never replaced.

use std::cell::RefCell;

use objc2::rc::Retained;
use objc2::runtime::{NSObjectProtocol, ProtocolObject};
use objc2::{define_class, msg_send, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{NSScrollView, NSTextDelegate, NSTextView, NSTextViewDelegate};
use objc2_foundation::{NSNotification, NSObject, NSRange, NSSize, NSString};

use egrio_ui::backend::{Event, UiEvent};
use egrio_ui::node::{TextEditor, TextStyle};
use egrio_ui::reconcile::NodeId;

use super::style;

pub struct EditorIvars {
    post: fn(UiEvent),
    id: NodeId,
    /// The text as last reported or written back.
    known: RefCell<String>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioTextEditorDelegate"]
    #[thread_kind = MainThreadOnly]
    #[ivars = EditorIvars]
    pub struct TextEditorDelegate;

    unsafe impl NSObjectProtocol for TextEditorDelegate {}

    unsafe impl NSTextDelegate for TextEditorDelegate {
        #[unsafe(method(textDidChange:))]
        fn did_change(&self, notification: &NSNotification) {
            let Some(view) = notification
                .object()
                .and_then(|object| object.downcast::<NSTextView>().ok())
            else {
                return;
            };
            let ivars = self.ivars();
            let text = view.string().to_string();
            if *ivars.known.borrow() == text {
                return;
            }
            *ivars.known.borrow_mut() = text.clone();
            (ivars.post)(UiEvent::Node {
                id: ivars.id,
                event: Event::Changed(text),
            });
        }
    }

    unsafe impl NSTextViewDelegate for TextEditorDelegate {}
);

pub fn text_editor(
    mtm: MainThreadMarker,
    props: &TextEditor,
    post: fn(UiEvent),
    id: NodeId,
) -> (
    Retained<NSScrollView>,
    Retained<NSTextView>,
    Retained<TextEditorDelegate>,
) {
    let scroll = NSTextView::scrollableTextView(mtm);
    let view = scroll
        .documentView()
        .and_then(|view| view.downcast::<NSTextView>().ok())
        .expect("a scrollable text view holds a text view");
    view.setRichText(false);
    view.setImportsGraphics(false);
    view.setUsesFontPanel(false);
    view.setAllowsUndo(true);
    view.setUsesFindBar(true);
    view.setIncrementalSearchingEnabled(true);
    // YAML is written as typed: no smart quotes, dashes, replacements,
    // corrections, links or completions.
    view.setAutomaticQuoteSubstitutionEnabled(false);
    view.setAutomaticDashSubstitutionEnabled(false);
    view.setAutomaticTextReplacementEnabled(false);
    view.setAutomaticSpellingCorrectionEnabled(false);
    view.setContinuousSpellCheckingEnabled(false);
    view.setGrammarCheckingEnabled(false);
    view.setAutomaticLinkDetectionEnabled(false);
    view.setAutomaticDataDetectionEnabled(false);
    view.setSmartInsertDeleteEnabled(false);
    view.setAutomaticTextCompletionEnabled(false);
    view.setFont(Some(&style::font(TextStyle::Mono)));
    view.setTextContainerInset(NSSize::new(8.0, 10.0));
    let delegate = TextEditorDelegate::alloc(mtm).set_ivars(EditorIvars {
        post,
        id,
        known: RefCell::new(String::new()),
    });
    let delegate: Retained<TextEditorDelegate> = unsafe { msg_send![super(delegate), init] };
    // The delegate is weak; the realized node keeps it alive.
    view.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    style_text_editor(&view, &delegate, props);
    (scroll, view, delegate)
}

pub fn style_text_editor(view: &NSTextView, delegate: &TextEditorDelegate, props: &TextEditor) {
    let known = &delegate.ivars().known;
    if known.borrow().as_str() != &*props.text {
        // Known first: the text view might report the text it is given.
        *known.borrow_mut() = props.text.to_string();
        view.setString(&NSString::from_str(&props.text));
        view.setSelectedRange(NSRange::new(0, 0));
        // Its undo history was of another text.
        if let Some(undo) = view.undoManager() {
            undo.removeAllActions();
        }
    }
    view.setEditable(props.enabled);
}

/// Puts the caret at the `index`th character, scrolls it into view and
/// points at it.
pub fn reveal(view: &NSTextView, index: usize) {
    let text = view.string().to_string();
    let mut chars = text.chars().skip(index);
    let at: usize = text.chars().take(index).map(char::len_utf16).sum();
    if let Some(window) = view.window() {
        window.makeFirstResponder(Some(view));
    }
    let caret = NSRange::new(at, 0);
    view.setSelectedRange(caret);
    view.scrollRangeToVisible(caret);
    // The find indicator needs a character to light up.
    if let Some(character) = chars.next().filter(|character| *character != '\n') {
        view.showFindIndicatorForRange(NSRange::new(at, character.len_utf16()));
    }
}
