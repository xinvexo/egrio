//! Watches what the running Core decides for itself: which member each
//! automatic policy group uses (see
//! [`egrio_core::CorePolicyState::automatic_members`]). Health probes and
//! ejections move it with neither the user nor the profile moving, and the
//! Core advances nothing a host could wait on when they do — a probe
//! latency that re-ranks a UrlTest group changes no live flow's route — so
//! the app reads the report on its own timer and publishes the move for the
//! tray and the nodes page. It runs for the app's lifetime, whether a
//! window shows or not, because the tray names the member with no window
//! open.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::runtime::DesktopRuntime;

/// How often the report is read. The members move on probe outcomes, whose
/// interval is each group's own (300 seconds by default), and on dial
/// failures, which eject a node within seconds.
const POLL: Duration = Duration::from_secs(5);

/// A running Core's profile and the members its automatic groups use.
type Report = (String, BTreeMap<String, String>);

/// Starts the watch. Call once, after the Runtime host exists.
pub fn init(runtime: &DesktopRuntime) {
    let runtime = runtime.clone();
    crate::async_runtime::spawn(async move {
        let mut last = None;
        let mut poll = tokio::time::interval(POLL);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            poll.tick().await;
            let current = report(&runtime);
            if moved(&last, &current) {
                crate::events::notify_group_members_changed();
            }
            last = current;
        }
    });
}

fn report(runtime: &DesktopRuntime) -> Option<Report> {
    runtime
        .effective_core_policy()
        .map(|policy| (policy.profile_id, policy.automatic_members))
}

/// Whether the hosts have to hear about the move. A Core that started or
/// stopped is a native state change they already follow, and its first
/// report is what they read then; from there on every move of a member is
/// theirs to show.
fn moved(last: &Option<Report>, current: &Option<Report>) -> bool {
    last.is_some() && current.is_some() && last != current
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(profile: &str, members: &[(&str, &str)]) -> Option<Report> {
        Some((
            profile.to_string(),
            members
                .iter()
                .map(|(group, member)| ((*group).into(), (*member).into()))
                .collect(),
        ))
    }

    #[test]
    fn only_a_move_between_two_reports_is_published() {
        let fast = report("p", &[("Auto", "HK")]);
        let other = report("p", &[("Auto", "TW")]);
        assert!(moved(&fast, &other), "another member");
        assert!(!moved(&fast, &fast), "the same report");
        assert!(!moved(&None, &fast), "a Core that started");
        assert!(!moved(&fast, &None), "a Core that stopped");
        assert!(!moved(&None, &None), "no Core");
        assert!(
            moved(&fast, &report("q", &[("Auto", "HK")])),
            "another profile's report is a move too"
        );
    }
}
