//! The changes a desktop host reacts to: a Runtime, capture or Core
//! transition that landed, a change to the profiles, and notices about TUN
//! mode and the system proxy. The backend publishes them on one broadcast
//! channel; each host subscribes and forwards them to its windows and tray.
//! The signals carry no state the host needs: a subscription that falls
//! behind receives a state change and a profile change in place of what it
//! lost, and re-reading what its windows show recovers it; only the notices
//! it lost are gone. A headless path publishes to no one.

use std::sync::LazyLock;

use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopEvent {
    /// A Runtime, capture or Core state transition landed.
    NativeStateChanged,
    /// Required configuration data could not be prepared or activated.
    CorePreparationFailed { message: String },
    /// Profile contents, the active profile, or a persisted policy-group
    /// choice changed.
    ProfilesChanged,
    /// The running Core uses another member of an automatic policy group
    /// (see [`crate::policy_watch`]).
    GroupMembersChanged,
    /// The Windows system-proxy guard acted on another program's change;
    /// `message` is the English diagnostic detail, the host owns the wording.
    SystemProxyGuard {
        notice: SystemProxyGuardNotice,
        message: String,
    },
    /// TUN mode's platform session changed on its own; `message` is the
    /// English diagnostic detail.
    TunSession {
        notice: TunSessionNotice,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxyGuardNotice {
    /// It put the system proxy back over the change.
    Reasserted,
    /// It gave way to the change and removed the system proxy layer.
    Yielded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunSessionNotice {
    /// The session ended on its own.
    Interrupted,
    /// It was restored.
    Recovered,
    /// It could not be restored.
    Failed,
}

/// A host's subscription to the events published after it began.
pub struct Subscription {
    events: broadcast::Receiver<DesktopEvent>,
    /// The profile change still owed after falling behind.
    owes_profiles: bool,
}

impl Subscription {
    /// The next event, or `None` once nothing can publish anymore.
    pub async fn recv(&mut self) -> Option<DesktopEvent> {
        if std::mem::take(&mut self.owes_profiles) {
            return Some(DesktopEvent::ProfilesChanged);
        }
        match self.events.recv().await {
            Ok(event) => Some(event),
            Err(RecvError::Lagged(_)) => {
                self.owes_profiles = true;
                Some(DesktopEvent::NativeStateChanged)
            }
            Err(RecvError::Closed) => None,
        }
    }
}

static CHANNEL: LazyLock<broadcast::Sender<DesktopEvent>> =
    LazyLock::new(|| broadcast::channel(64).0);

/// Every event published after this call.
pub fn subscribe() -> Subscription {
    Subscription {
        events: CHANNEL.subscribe(),
        owes_profiles: false,
    }
}

fn publish(event: DesktopEvent) {
    // No subscriber is not an error: headless paths publish to no one.
    let _ = CHANNEL.send(event);
}

pub fn notify_core_preparation_failed(message: String) {
    publish(DesktopEvent::CorePreparationFailed { message });
}

pub fn notify_native_state_changed() {
    publish(DesktopEvent::NativeStateChanged);
}

pub fn notify_group_members_changed() {
    publish(DesktopEvent::GroupMembersChanged);
}

/// Publishes [`DesktopEvent::NativeStateChanged`] once when dropped, so an
/// operation that mutates native state signals on every return path,
/// including `?` early exits and per-platform `cfg` branches, from a single
/// guard at its top.
#[must_use = "hold the guard until the operation returns"]
pub struct NotifyOnReturn;

pub fn notify_on_return() -> NotifyOnReturn {
    NotifyOnReturn
}

impl Drop for NotifyOnReturn {
    fn drop(&mut self) {
        notify_native_state_changed();
    }
}

/// Publishes [`DesktopEvent::ProfilesChanged`] once when dropped.
#[must_use = "hold the guard until the profile operation returns"]
pub struct NotifyProfilesOnReturn;

pub fn notify_profiles_on_return() -> NotifyProfilesOnReturn {
    NotifyProfilesOnReturn
}

impl Drop for NotifyProfilesOnReturn {
    fn drop(&mut self) {
        publish(DesktopEvent::ProfilesChanged);
    }
}

#[cfg(windows)]
pub fn notify_system_proxy_guard(notice: SystemProxyGuardNotice, message: String) {
    publish(DesktopEvent::SystemProxyGuard { notice, message });
}

pub fn notify_tun_session(notice: TunSessionNotice, message: String) {
    publish(DesktopEvent::TunSession { notice, message });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_subscription_that_falls_behind_is_told_to_read_again() {
        let mut events = subscribe();
        for _ in 0..100 {
            notify_tun_session(TunSessionNotice::Recovered, String::new());
        }
        assert_eq!(events.recv().await, Some(DesktopEvent::NativeStateChanged));
        assert_eq!(events.recv().await, Some(DesktopEvent::ProfilesChanged));
        assert!(matches!(
            events.recv().await,
            Some(DesktopEvent::TunSession { .. })
        ));
    }
}
