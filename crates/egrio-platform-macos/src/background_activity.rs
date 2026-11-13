//! Process activity used by the desktop Runtime owner while macOS capture is
//! active: Foundation's `NSProcessInfo beginActivityWithOptions:reason:` with
//! `NSActivityUserInitiatedAllowingIdleSystemSleep` keeps the app and Core
//! schedulable when hidden or screen-locked (it includes sudden and automatic
//! termination protection and opts out of App Nap) without preventing
//! display-off or idle sleep (`NSProcessInfo.h`).

use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::{NSActivityOptions, NSObjectProtocol, NSProcessInfo, NSString};

/// The activity token Foundation returned. `endActivity:` takes it from any
/// thread, and nothing else touches it.
struct Activity(Retained<ProtocolObject<dyn NSObjectProtocol>>);

// SAFETY: the token is an opaque object only ever passed back to
// `endActivity:`, which NSProcessInfo accepts on any thread.
unsafe impl Send for Activity {}

/// Balanced claims on the one process activity.
struct Claims {
    count: usize,
    activity: Option<Activity>,
}

static CLAIMS: Mutex<Claims> = Mutex::new(Claims {
    count: 0,
    activity: None,
});

fn claims() -> std::sync::MutexGuard<'static, Claims> {
    CLAIMS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One balanced claim on the process-wide Runtime background activity.
/// Dropping the last claim ends the Foundation activity.
#[derive(Debug)]
pub struct MacosRuntimeBackgroundActivity {
    _claim: (),
}

impl MacosRuntimeBackgroundActivity {
    pub fn begin() -> Self {
        let mut claims = claims();
        claims.count += 1;
        if claims.count == 1 {
            let reason = NSString::from_str("Egrio proxy Runtime is serving network traffic");
            let token = NSProcessInfo::processInfo().beginActivityWithOptions_reason(
                NSActivityOptions::UserInitiatedAllowingIdleSystemSleep,
                &reason,
            );
            claims.activity = Some(Activity(token));
        }
        Self { _claim: () }
    }
}

impl Drop for MacosRuntimeBackgroundActivity {
    fn drop(&mut self) {
        let mut claims = claims();
        claims.count -= 1;
        if claims.count == 0 {
            if let Some(Activity(token)) = claims.activity.take() {
                // SAFETY: the token came from `beginActivityWithOptions:reason:`.
                unsafe { NSProcessInfo::processInfo().endActivity(&token) };
            }
        }
    }
}

/// Read-only lifecycle evidence for host tests and diagnostics.
pub fn runtime_background_activity_is_active() -> bool {
    claims().activity.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_claims_hold_one_process_activity_until_the_last_drop() {
        assert!(!runtime_background_activity_is_active());
        let first = MacosRuntimeBackgroundActivity::begin();
        assert!(runtime_background_activity_is_active());
        let second = MacosRuntimeBackgroundActivity::begin();
        drop(first);
        assert!(runtime_background_activity_is_active());
        drop(second);
        assert!(!runtime_background_activity_is_active());
    }
}
