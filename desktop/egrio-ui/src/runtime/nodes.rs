//! The nodes page's reads and actions, and the latency tests: the active
//! profile's nodes, groups and the members its groups use follow the
//! profile, and tests start as places in the queue free up.

use egrio_core::TrafficPolicyMode;
use egrio_desktop::operations::profiles;

use super::Ui;
use crate::backend::Backend;
use crate::latency::{group_targets, ProbeTarget};
use crate::msg::{Msg, NodesMsg};
use crate::pages::nodes::{
    chosen, entry_targets, global_outbounds, member_targets, Entry, Inventory,
};
use crate::state::{Change, Remote, Section};
use egrio_desktop::operations::profiles::GroupMembers;

impl<B: Backend> Ui<B> {
    /// Reads the active profile's nodes, groups and the members its groups
    /// use.
    pub(super) fn load_nodes(&self) {
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let runtime = self.desktop.runtime.clone();
        let (profile_id, source_revision) = (profile.id.clone(), profile.source_revision.clone());
        self.spawn_blocking(move || {
            let result = profiles::profile_inventory(profile_id.clone()).map(|inventory| {
                let members =
                    profiles::group_members(&runtime, profile_id).unwrap_or_else(|error| {
                        log::warn!("group members unavailable: {error}");
                        GroupMembers::default()
                    });
                Inventory {
                    source_revision,
                    inventory,
                    selections: members.chosen,
                    automatic: members.automatic,
                }
            });
            Msg::Nodes(NodesMsg::Loaded(result))
        });
    }

    /// Reads the members the active profile's groups use, which change
    /// without its file changing: the user's choices, and the running
    /// Core's own for the automatic groups.
    pub(super) fn load_group_members(&self) {
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let (runtime, profile_id) = (self.desktop.runtime.clone(), profile.id.clone());
        self.spawn_blocking(move || {
            let result = profiles::group_members(&runtime, profile_id.clone());
            Msg::Nodes(NodesMsg::Members { profile_id, result })
        });
    }

    /// The active profile was read: what the nodes page shows follows it,
    /// read again when its file changed, and its group choices whenever
    /// the page shows.
    pub(super) fn nodes_follow_profile(&self) {
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let current = self
            .state
            .nodes
            .inventory()
            .ready()
            .is_some_and(|inventory| {
                inventory.inventory.profile_id == profile.id
                    && inventory.source_revision == profile.source_revision
            });
        if !current {
            self.load_nodes();
        } else if self.state.section == Section::Nodes {
            self.load_group_members();
        }
    }

    /// The nodes and groups read for the active profile.
    fn current_inventory(&self) -> Option<&Inventory> {
        let profile = self.state.active_profile.ready().and_then(Option::as_ref)?;
        self.state
            .nodes
            .inventory()
            .ready()
            .filter(|inventory| inventory.inventory.profile_id == profile.id)
    }

    pub(super) fn nodes(&mut self, msg: NodesMsg) {
        match msg {
            NodesMsg::Show(key) => {
                // A list that lost its selection keeps showing its entry.
                if Entry::from_key(&key).is_some() {
                    self.state.nodes.shown = Some(key);
                    self.remember();
                }
            }
            NodesMsg::TestEntry(key) => {
                let (Some(entry), Some(inventory)) =
                    (Entry::from_key(&key), self.current_inventory())
                else {
                    return;
                };
                let targets = entry_targets(&inventory.inventory, &entry);
                self.state.latency.request(targets);
                self.start_tests();
            }
            NodesMsg::TestMember(name) => {
                let Some(inventory) = self.current_inventory() else {
                    return;
                };
                let targets = member_targets(&inventory.inventory, &name);
                self.state.latency.request(targets);
                self.start_tests();
            }
            NodesMsg::TestGroup(id) => {
                let Some(inventory) = self.current_inventory() else {
                    return;
                };
                let targets = group_targets(&inventory.inventory, &id);
                self.state.latency.request(targets);
                self.start_tests();
            }
            NodesMsg::SetGlobalOutbound(outbound) => self.set_global_outbound(outbound),
            NodesMsg::GlobalOutboundSet(result) => {
                let failed = self.state.text().global_outbound_failed();
                self.policy_changed(result, failed);
            }
            NodesMsg::Loaded(result) => {
                let active = self
                    .state
                    .active_profile
                    .ready()
                    .and_then(Option::as_ref)
                    .map(|profile| profile.id.clone());
                match result {
                    Ok(inventory) if Some(&inventory.inventory.profile_id) == active.as_ref() => {
                        self.state.latency.retain_current(&inventory.inventory);
                        self.state.nodes.set_inventory(Remote::Ready(inventory));
                    }
                    // Read for a profile no longer in use.
                    Ok(_) => {}
                    Err(error) => self.state.nodes.set_inventory(Remote::Failed(error)),
                }
            }
            NodesMsg::Members { profile_id, result } => match result {
                Ok(members) => self.state.nodes.set_members(&profile_id, members),
                Err(error) => log::warn!("group members unavailable: {error}"),
            },
        }
    }

    /// Chooses a Select group's member, as the page or the tray asks; the
    /// member shows chosen from the click on.
    pub(super) fn select_member(&mut self, group_id: String, member: String) {
        if self.state.transition_pending() {
            return;
        }
        let Some(inventory) = self.current_inventory() else {
            return;
        };
        let Some(group) = inventory.inventory.groups.iter().find(|group| {
            group.id == group_id && group.kind == "select" && group.members.contains(&member)
        }) else {
            return;
        };
        if chosen(&inventory.selections, group) == Some(member.as_str()) {
            return;
        }
        let profile_id = inventory.inventory.profile_id.clone();
        let runtime = self.desktop.runtime.clone();
        let change = Change::Member {
            group_id: group_id.clone(),
            member: member.clone(),
        };
        self.begin_change(change, async move {
            Msg::MemberSelected(
                profiles::set_group_selection(&runtime, profile_id, group_id, member).await,
            )
        });
    }

    fn set_global_outbound(&mut self, outbound: String) {
        if self.state.transition_pending() {
            return;
        }
        let Some(profile) = self.state.active_profile.ready().and_then(Option::as_ref) else {
            return;
        };
        let offered = self.current_inventory().is_some_and(|inventory| {
            global_outbounds(&inventory.inventory, profile.global_outbound.as_deref())
                .contains(&outbound)
        });
        if !offered
            || profile.traffic_policy_mode != TrafficPolicyMode::Global
            || profile.global_outbound.as_deref() == Some(outbound.as_str())
        {
            return;
        }
        let (runtime, profile_id) = (self.desktop.runtime.clone(), profile.id.clone());
        self.begin_change(Change::GlobalOutbound(outbound.clone()), async move {
            Msg::Nodes(NodesMsg::GlobalOutboundSet(
                profiles::set_profile_traffic_policy(
                    &runtime,
                    profile_id,
                    TrafficPolicyMode::Global,
                    Some(outbound),
                )
                .await,
            ))
        });
    }

    /// A test ended: its place goes to the next one waiting.
    pub(super) fn measured(&mut self, target: ProbeTarget, result: Result<u32, String>) {
        self.state.latency.finish(target, result);
        self.start_tests();
    }

    /// Starts the waiting tests that have a place.
    fn start_tests(&mut self) {
        for target in self.state.latency.start() {
            let runtime = self.desktop.runtime.clone();
            self.spawn(async move {
                let (profile_id, node) = (target.profile_id.clone(), target.node.clone());
                // A test that panics still gives its place back.
                let result = egrio_desktop::async_runtime::spawn(async move {
                    profiles::test_node_latency(&runtime, profile_id, node).await
                })
                .await
                .unwrap_or_else(|error| Err(error.to_string()));
                Msg::Measured { target, result }
            });
        }
    }
}
