//! The Objective-C target every control's action reaches: a closure that
//! turns the action into an interface event. A control holds its target
//! weakly, so whoever owns the control keeps the target.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObjectProtocol, Sel};
use objc2::{define_class, msg_send, sel, DeclaredClass, MainThreadMarker, MainThreadOnly};
use objc2_foundation::NSObject;

pub struct TargetIvars {
    action: Box<dyn Fn(&AnyObject)>,
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "EgrioActionTarget"]
    #[thread_kind = MainThreadOnly]
    #[ivars = TargetIvars]
    pub struct ActionTarget;

    unsafe impl NSObjectProtocol for ActionTarget {}

    impl ActionTarget {
        #[unsafe(method(perform:))]
        fn perform(&self, sender: &AnyObject) {
            (self.ivars().action)(sender);
        }
    }
);

impl ActionTarget {
    pub fn new(mtm: MainThreadMarker, action: impl Fn(&AnyObject) + 'static) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(TargetIvars {
            action: Box::new(action),
        });
        unsafe { msg_send![super(this), init] }
    }

    pub fn selector() -> Sel {
        sel!(perform:)
    }
}
