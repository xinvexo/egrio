//! Latency tests of the profiles' nodes, one record for every window that
//! starts or shows them: a test is one request for the node's test URL
//! through it (see `egrio_desktop::network_probe::test_node_latency`), and
//! a few run at a time while the rest wait their turn. A result belongs to
//! what it measured, so a node whose server, port, test URL or dialer
//! changed shows none; results last while the app runs and are never saved.

use std::collections::{HashMap, HashSet, VecDeque};

use egrio_desktop::profile_store::{ProfileInventory, SavedPolicyGroup, SavedProxyNode};

/// Tests that run at once.
pub const CONCURRENCY: usize = 10;

/// A round trip as the page and the tray show it, in whole milliseconds: a
/// LAN endpoint answers in under one.
pub fn milliseconds_text(milliseconds: u32) -> String {
    if milliseconds < 1 {
        "<1 ms".into()
    } else {
        format!("{milliseconds} ms")
    }
}

/// The color that rates a round trip: green under 200 ms, orange under 500.
pub fn milliseconds_tone(milliseconds: u32) -> crate::node::Tone {
    use crate::node::Tone;
    match milliseconds {
        0..200 => Tone::Success,
        200..500 => Tone::Warning,
        _ => Tone::Danger,
    }
}

/// A node as a test measures it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProbeTarget {
    pub profile_id: String,
    pub node: String,
    server: Option<String>,
    port: Option<u16>,
    test_url: Option<String>,
    dialer_proxy: Option<String>,
}

/// Whether a node is ever tested: hidden nodes and those the Core cannot
/// connect through are not.
pub fn testable(node: &SavedProxyNode) -> bool {
    !node.hidden && node.unsupported.is_none()
}

impl ProbeTarget {
    /// `node` of the profile as a test measures it, if it is [`testable`].
    pub fn of(profile_id: &str, node: &SavedProxyNode) -> Option<Self> {
        testable(node).then(|| Self {
            profile_id: profile_id.into(),
            node: node.name.clone(),
            server: node.server.clone(),
            port: node.port,
            test_url: node.test_url.clone(),
            dialer_proxy: node.dialer_proxy.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// Waiting for its turn or running.
    Testing,
    /// The round trip, in milliseconds.
    Ready(u32),
    /// Why the test failed.
    Failed(String),
}

#[derive(Debug, Default)]
pub struct Latency {
    results: HashMap<ProbeTarget, Probe>,
    /// Tests waiting their turn, oldest first.
    queue: VecDeque<ProbeTarget>,
    running: usize,
    /// Counts the changes, which tells a view built from the results that
    /// it is out of date.
    revision: u64,
}

impl Latency {
    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn get(&self, target: &ProbeTarget) -> Option<&Probe> {
        self.results.get(target)
    }

    /// Asks for tests of `targets`; one already testing keeps its place.
    pub fn request(&mut self, targets: impl IntoIterator<Item = ProbeTarget>) {
        self.revision += 1;
        for target in targets {
            if self.results.get(&target) != Some(&Probe::Testing) {
                self.results.insert(target.clone(), Probe::Testing);
                self.queue.push_back(target);
            }
        }
    }

    /// Whether any of `targets` is testing.
    pub fn testing<'a>(&self, mut targets: impl Iterator<Item = &'a ProbeTarget>) -> bool {
        targets.any(|target| self.results.get(target) == Some(&Probe::Testing))
    }

    /// The tests to start now: as many waiting ones as there are free places.
    pub fn start(&mut self) -> Vec<ProbeTarget> {
        let free = CONCURRENCY.saturating_sub(self.running);
        let started: Vec<ProbeTarget> = self.queue.drain(..free.min(self.queue.len())).collect();
        self.running += started.len();
        started
    }

    /// A test's result, which frees its place.
    pub fn finish(&mut self, target: ProbeTarget, result: Result<u32, String>) {
        self.revision += 1;
        self.running = self.running.saturating_sub(1);
        let probe = match result {
            Ok(milliseconds) => Probe::Ready(milliseconds),
            Err(error) => Probe::Failed(error),
        };
        self.results.insert(target, probe);
    }

    /// Forgets the profile's results for nodes that are gone or changed.
    pub fn retain_current(&mut self, inventory: &ProfileInventory) {
        self.revision += 1;
        let current: HashSet<ProbeTarget> = inventory
            .proxies
            .iter()
            .filter_map(|node| ProbeTarget::of(&inventory.profile_id, node))
            .collect();
        self.results.retain(|target, probe| {
            target.profile_id != inventory.profile_id
                || current.contains(target)
                || *probe == Probe::Testing
        });
    }
}

/// The profile's nodes by their names.
pub fn nodes_by_name(inventory: &ProfileInventory) -> HashMap<&str, &SavedProxyNode> {
    inventory
        .proxies
        .iter()
        .map(|node| (node.name.as_str(), node))
        .collect()
}

/// The nodes a policy group reaches, through its nested groups too, each
/// once, in the order the members list them; DIRECT and REJECT are none.
/// The walk goes only as far as it is asked to.
pub struct GroupNodes<'a> {
    inventory: &'a ProfileInventory,
    nodes: &'a HashMap<&'a str, &'a SavedProxyNode>,
    /// The members still to visit, the next one last.
    waiting: Vec<&'a str>,
    visited: HashSet<&'a str>,
}

impl<'a> GroupNodes<'a> {
    pub fn of(
        inventory: &'a ProfileInventory,
        nodes: &'a HashMap<&'a str, &'a SavedProxyNode>,
        group: &'a SavedPolicyGroup,
    ) -> Self {
        Self {
            inventory,
            nodes,
            waiting: group.members.iter().rev().map(String::as_str).collect(),
            visited: HashSet::from([group.name.as_str()]),
        }
    }
}

impl<'a> Iterator for GroupNodes<'a> {
    type Item = &'a SavedProxyNode;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(member) = self.waiting.pop() {
            if !self.visited.insert(member) {
                continue;
            }
            if let Some(node) = self.nodes.get(member) {
                return Some(node);
            }
            let nested = self
                .inventory
                .groups
                .iter()
                .find(|group| group.name == member);
            if let Some(group) = nested {
                self.waiting
                    .extend(group.members.iter().rev().map(String::as_str));
            }
        }
        None
    }
}

/// The tests of a policy group: one for each node it reaches that is ever
/// tested.
pub fn group_targets(inventory: &ProfileInventory, group_id: &str) -> Vec<ProbeTarget> {
    let Some(group) = inventory.groups.iter().find(|group| group.id == group_id) else {
        return Vec::new();
    };
    let nodes = nodes_by_name(inventory);
    GroupNodes::of(inventory, &nodes, group)
        .filter_map(|node| ProbeTarget::of(&inventory.profile_id, node))
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn node(name: &str) -> SavedProxyNode {
        SavedProxyNode {
            id: format!("node-{name}"),
            name: name.into(),
            protocol: "trojan".into(),
            server: Some(format!("{name}.example")),
            port: Some(443),
            sort_order: 0,
            unsupported: None,
            hidden: false,
            test_url: None,
            dialer_proxy: None,
        }
    }

    pub(crate) fn group(name: &str, kind: &str, members: &[&str]) -> SavedPolicyGroup {
        SavedPolicyGroup {
            id: format!("group-{name}"),
            name: name.into(),
            kind: kind.into(),
            members: members.iter().map(|member| (*member).into()).collect(),
            sort_order: 0,
        }
    }

    pub(crate) fn inventory(
        proxies: Vec<SavedProxyNode>,
        groups: Vec<SavedPolicyGroup>,
    ) -> ProfileInventory {
        ProfileInventory {
            profile_id: "p".into(),
            proxies,
            groups,
        }
    }

    fn names(targets: &[ProbeTarget]) -> Vec<&str> {
        targets.iter().map(|target| target.node.as_str()).collect()
    }

    #[test]
    fn a_group_reaches_each_node_once_through_nested_groups_and_cycles() {
        let mut hidden = node("Hidden");
        hidden.hidden = true;
        let mut unsupported = node("VMess");
        unsupported.unsupported = Some("vmess nodes are not supported yet".into());
        let inventory = inventory(
            vec![node("HK"), node("TW"), hidden, unsupported],
            vec![
                group(
                    "Proxy",
                    "select",
                    &["Auto", "HK", "DIRECT", "REJECT", "Hidden"],
                ),
                group(
                    "Auto",
                    "url-test",
                    &["HK", "TW", "Proxy", "VMess", "missing"],
                ),
            ],
        );
        assert_eq!(
            names(&group_targets(&inventory, "group-Proxy")),
            ["HK", "TW"]
        );
        assert!(group_targets(&inventory, "group-missing").is_empty());
    }

    #[test]
    fn tests_run_a_few_at_a_time_and_a_running_one_is_not_asked_for_twice() {
        let mut latency = Latency::default();
        let inventory = inventory(
            (0..CONCURRENCY + 2)
                .map(|index| node(&format!("N{index}")))
                .collect(),
            Vec::new(),
        );
        let targets: Vec<ProbeTarget> = inventory
            .proxies
            .iter()
            .filter_map(|node| ProbeTarget::of("p", node))
            .collect();
        latency.request(targets.clone());
        let started = latency.start();
        assert_eq!(started.len(), CONCURRENCY);
        assert!(latency.start().is_empty(), "every place is taken");
        latency.request([targets[0].clone()]);
        latency.finish(started[0].clone(), Ok(42));
        assert_eq!(latency.get(&targets[0]), Some(&Probe::Ready(42)));
        assert_eq!(
            latency.start().len(),
            1,
            "the freed place goes to the next one"
        );
        assert!(latency.testing(targets.iter()));
        for target in started.into_iter().skip(1) {
            latency.finish(target, Err("timed out".into()));
        }
        let last = latency.start();
        assert_eq!(last.len(), 1);
        latency.finish(targets[CONCURRENCY].clone(), Ok(7));
        assert!(
            latency.testing(targets.iter()),
            "one of the list is still running"
        );
        latency.finish(last[0].clone(), Ok(9));
        assert!(!latency.testing(targets.iter()));
        assert_eq!(
            latency.get(&targets[1]),
            Some(&Probe::Failed("timed out".into()))
        );
    }

    #[test]
    fn a_changed_node_shows_no_old_result() {
        let mut latency = Latency::default();
        let before = inventory(vec![node("HK")], Vec::new());
        let target = ProbeTarget::of("p", &before.proxies[0]).unwrap();
        latency.request([target.clone()]);
        latency.start();
        latency.finish(target.clone(), Ok(42));
        let mut moved = node("HK");
        moved.port = Some(8443);
        let after = inventory(vec![moved], Vec::new());
        let changed = ProbeTarget::of("p", &after.proxies[0]).unwrap();
        assert_eq!(latency.get(&changed), None);
        latency.retain_current(&after);
        assert_eq!(latency.get(&target), None, "the old result is forgotten");
    }

    #[test]
    fn hidden_and_unsupported_nodes_are_never_tested() {
        let mut hidden = node("HK");
        hidden.hidden = true;
        assert!(ProbeTarget::of("p", &hidden).is_none());
        let mut unsupported = node("HK");
        unsupported.unsupported = Some("no".into());
        assert!(ProbeTarget::of("p", &unsupported).is_none());
        assert!(ProbeTarget::of("p", &node("HK")).is_some());
    }
}
