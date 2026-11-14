//! The nodes page: what traffic goes through, and choosing it. A rail of
//! cards at the right names what can be shown: in Global mode the global
//! outbound first, then each policy group with the member it uses and its
//! latency. The rest of the page shows the shown entry's members as tiles.
//! Over the tiles and over the rail a caption names them and counts them,
//! and nothing more: the shown card already names the entry, its kind and
//! what it uses. Pressing a
//! member chooses it where the entry makes a
//! choice (a Select group's member, the global outbound) and marks it with
//! a check; pressing a card shows its entry. A tile's latency, on a member
//! or a card, is a button of its own that tests it, a card's everything its
//! entry lists. A node tile notes the outbound it dials through and its own
//! test URL; a group tile shows the member it uses. A profile without groups
//! shows every node outside Global mode, with no rail.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use egrio_core::TrafficPolicyMode;
use egrio_desktop::models::SavedProfileSummary;
use egrio_desktop::operations::profiles::GroupMembers;
use egrio_desktop::profile_store::{ProfileInventory, SavedPolicyGroup, SavedProxyNode};

use crate::latency::{
    group_targets, milliseconds_text, milliseconds_tone, testable, Latency, Probe, ProbeTarget,
};
use crate::msg::{Msg, NodesMsg};
use crate::node::{
    caption, card, column, placeholder, stack, tiles, Axis, CrossAlign, Handler, Icon, Node, Tile,
    TileValue, Tiles, Tone,
};
use crate::state::{Remote, State};
use crate::text::{Lang, Text};

const TILE_MIN_WIDTH: f64 = 180.0;
/// The tiles' and the rail's cards' one height, so their rows line up.
const TILE_HEIGHT: f64 = 60.0;
/// The rail's width; its cards are one to a row.
const RAIL_WIDTH: f64 = 220.0;

/// What the list offers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Entry {
    /// Global mode's outbound: the groups and the nodes the Core can use.
    Global,
    /// A policy group, by its id.
    Group(String),
    /// Every node the profile lists, which the page shows when the rail
    /// has nothing: a profile without groups outside Global mode.
    All,
}

impl Entry {
    /// Its key in the list, which the interface remembers.
    pub fn key(&self) -> String {
        match self {
            Entry::Global => "global".into(),
            Entry::Group(id) => format!("group:{id}"),
            Entry::All => "all".into(),
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "global" => Some(Entry::Global),
            "all" => Some(Entry::All),
            _ => key
                .strip_prefix("group:")
                .filter(|id| !id.is_empty())
                .map(|id| Entry::Group(id.into())),
        }
    }
}

/// The active profile's nodes and groups as last read: the source revision
/// they were read from, and the groups' choices by group id.
#[derive(Debug, Clone)]
pub struct Inventory {
    pub source_revision: String,
    pub inventory: ProfileInventory,
    /// The Select groups' choices, by group id.
    pub selections: HashMap<String, String>,
    /// The member each automatic group uses, by group id, as the running
    /// Core reports it; empty while no Core serves the profile.
    pub automatic: HashMap<String, String>,
}

/// A Select group's choice, or its first member before one is made.
pub fn chosen<'a>(
    selections: &'a HashMap<String, String>,
    group: &'a SavedPolicyGroup,
) -> Option<&'a str> {
    selections
        .get(&group.id)
        .filter(|chosen| group.members.contains(chosen))
        .or(group.members.first())
        .map(String::as_str)
}

/// A Select group's member as the controls show it: the one a running
/// change chooses, from the click on, else its choice.
fn shown_choice<'a>(
    state: &'a State,
    selections: &'a HashMap<String, String>,
    group: &'a SavedPolicyGroup,
) -> Option<&'a str> {
    state
        .choosing(&group.id)
        .or_else(|| chosen(selections, group))
}

/// The member a group uses, as the controls show it: a Select group's
/// choice, and for a group that chooses one itself the member the running
/// Core reports. Without a Core serving the profile only a Select group has
/// one, since nothing is dialling through the others.
pub fn member_in_use<'a>(
    state: &'a State,
    inventory: &'a Inventory,
    group: &'a SavedPolicyGroup,
) -> Option<&'a str> {
    if group.kind == "select" {
        return shown_choice(state, &inventory.selections, group);
    }
    inventory
        .automatic
        .get(&group.id)
        .map(String::as_str)
        .filter(|member| group.members.iter().any(|declared| declared == member))
}

/// What the nodes page keeps: the entry the user chose to see, the active
/// profile's nodes and groups as last read, and the cards and tiles built
/// for the last render, reused while nothing they show changed.
#[derive(Debug)]
pub struct NodesPage {
    /// The entry the user chose, by its key; one the rail no longer has
    /// gives way to the first that fits.
    pub shown: Option<String>,
    inventory: Remote<Inventory>,
    /// Counts the reads, which tells the memo the inventory changed.
    reads: u64,
    memo: RefCell<Option<Memo>>,
}

/// The rail's cards and the shown entry's tiles, with what they were built
/// from.
type Memo = (MemoKey, Rc<Vec<Tile>>, Rc<Vec<Tile>>);

/// Everything the cards and the tiles are built from besides the inventory.
#[derive(Debug, Clone, PartialEq)]
struct MemoKey {
    reads: u64,
    latency: u64,
    lang: Lang,
    entry: Entry,
    mode: TrafficPolicyMode,
    global: Option<String>,
    /// The member a running change chooses, by group id.
    choosing: Option<(String, String)>,
    /// A change runs long: no tile takes a press.
    waiting: bool,
}

impl Default for NodesPage {
    fn default() -> Self {
        Self {
            shown: None,
            inventory: Remote::Loading,
            reads: 0,
            memo: RefCell::new(None),
        }
    }
}

impl NodesPage {
    /// Gives back the cards and tiles built for the last render; the next
    /// builds them.
    pub fn forget_rows(&mut self) {
        *self.memo.get_mut() = None;
    }

    pub fn inventory(&self) -> &Remote<Inventory> {
        &self.inventory
    }

    /// Counts the reads of the inventory and the changes of its choices.
    pub fn reads(&self) -> u64 {
        self.reads
    }

    pub fn set_inventory(&mut self, inventory: Remote<Inventory>) {
        self.inventory = inventory;
        self.reads += 1;
    }

    /// The profile's groups' new members, where they changed.
    pub fn set_members(&mut self, profile_id: &str, members: GroupMembers) {
        if let Remote::Ready(inventory) = &mut self.inventory {
            if inventory.inventory.profile_id != profile_id
                || (inventory.selections == members.chosen
                    && inventory.automatic == members.automatic)
            {
                return;
            }
            inventory.selections = members.chosen;
            inventory.automatic = members.automatic;
            self.reads += 1;
        }
    }

    /// A group's choice the profile saved.
    pub fn set_choice(&mut self, profile_id: &str, group_id: &str, member: &str) {
        if let Remote::Ready(inventory) = &mut self.inventory {
            if inventory.inventory.profile_id == profile_id
                && inventory.selections.get(group_id).map(String::as_str) != Some(member)
            {
                inventory
                    .selections
                    .insert(group_id.to_string(), member.to_string());
                self.reads += 1;
            }
        }
    }

    /// The cards and the tiles for `key`, built by `build` unless the last
    /// render's still show what they would.
    fn built(
        &self,
        key: MemoKey,
        build: impl FnOnce() -> (Vec<Tile>, Vec<Tile>),
    ) -> (Rc<Vec<Tile>>, Rc<Vec<Tile>>) {
        if let Some((cached, cards, tiles)) = self.memo.borrow().as_ref() {
            if *cached == key {
                return (cards.clone(), tiles.clone());
            }
        }
        let (cards, tiles) = build();
        let (cards, tiles) = (Rc::new(cards), Rc::new(tiles));
        *self.memo.borrow_mut() = Some((key, cards.clone(), tiles.clone()));
        (cards, tiles)
    }
}

/// Protocol names are proper nouns, the same in every language.
fn protocol_label(protocol: &str) -> &str {
    match protocol {
        "direct" => "DIRECT",
        "reject" => "REJECT",
        "http" => "HTTP",
        "socks5" => "SOCKS5",
        "shadowsocks" => "Shadowsocks",
        "vmess" => "VMess",
        "vless" => "VLESS",
        "trojan" => "Trojan",
        "hysteria2" => "Hysteria2",
        "tuic" => "TUIC",
        "openvpn" => "OpenVPN",
        other => other,
    }
}

/// The group types as Clash spells them; unknown ones show as written.
fn kind_label(kind: &str) -> &str {
    match kind {
        "select" => "Select",
        "url-test" => "URL-Test",
        "fallback" => "Fallback",
        "load-balance" => "Load-Balance",
        "relay" => "Relay",
        other => other,
    }
}

/// The nodes the list of every node shows: all but the hidden ones.
pub fn listed_nodes(inventory: &ProfileInventory) -> impl Iterator<Item = &SavedProxyNode> {
    inventory.proxies.iter().filter(|node| !node.hidden)
}

/// What a test of every listed node asks for.
pub fn listed_targets(inventory: &ProfileInventory) -> Vec<ProbeTarget> {
    listed_nodes(inventory)
        .filter_map(|node| ProbeTarget::of(&inventory.profile_id, node))
        .collect()
}

/// What the global outbound can be: the groups first, then the nodes the
/// Core can connect through, and the saved one where it is neither.
pub fn global_outbounds(inventory: &ProfileInventory, saved: Option<&str>) -> Vec<String> {
    let mut names: Vec<String> = inventory
        .groups
        .iter()
        .map(|group| group.name.clone())
        .chain(
            inventory
                .proxies
                .iter()
                .filter(|node| node.unsupported.is_none())
                .map(|node| node.name.clone()),
        )
        .collect();
    if let Some(saved) = saved.filter(|saved| !names.iter().any(|name| name == saved)) {
        names.push(saved.into());
    }
    names
}

/// The global outbound the controls show: the saved one, or the first
/// group, which the Core uses without a choice.
pub fn shown_global<'a>(
    state: &'a State,
    profile: &'a SavedProfileSummary,
    inventory: &'a ProfileInventory,
) -> Option<&'a str> {
    state
        .global_outbound(profile)
        .or_else(|| inventory.groups.first().map(|group| group.name.as_str()))
}

/// The rail's entries for a profile in `mode`.
fn entries(inventory: &ProfileInventory, mode: TrafficPolicyMode) -> Vec<Entry> {
    let mut entries = Vec::with_capacity(inventory.groups.len() + 1);
    if mode == TrafficPolicyMode::Global {
        entries.push(Entry::Global);
    }
    entries.extend(
        inventory
            .groups
            .iter()
            .map(|group| Entry::Group(group.id.clone())),
    );
    entries
}

/// The entry the page shows: the one the user chose while the rail has it,
/// else Global mode's outbound, the first Select group, the first group or
/// every node.
pub fn shown_entry(
    shown: Option<&str>,
    inventory: &ProfileInventory,
    mode: TrafficPolicyMode,
) -> Entry {
    let entries = entries(inventory, mode);
    if let Some(entry) = shown
        .and_then(Entry::from_key)
        .filter(|entry| entries.contains(entry))
    {
        return entry;
    }
    if mode == TrafficPolicyMode::Global {
        return Entry::Global;
    }
    inventory
        .groups
        .iter()
        .find(|group| group.kind == "select")
        .or(inventory.groups.first())
        .map_or(Entry::All, |group| Entry::Group(group.id.clone()))
}

/// What testing the entry asks for: the nodes a group reaches, or every
/// listed node.
pub fn entry_targets(inventory: &ProfileInventory, entry: &Entry) -> Vec<ProbeTarget> {
    match entry {
        Entry::Group(id) => group_targets(inventory, id),
        Entry::Global | Entry::All => listed_targets(inventory),
    }
}

/// What testing a member asks for: a node itself, or the nodes a group
/// reaches.
pub fn member_targets(inventory: &ProfileInventory, member: &str) -> Vec<ProbeTarget> {
    if let Some(node) = inventory.proxies.iter().find(|node| node.name == member) {
        return ProbeTarget::of(&inventory.profile_id, node)
            .into_iter()
            .collect();
    }
    inventory
        .groups
        .iter()
        .find(|group| group.name == member)
        .map(|group| group_targets(inventory, &group.id))
        .unwrap_or_default()
}

/// A latency as a tile shows it, a group's derived from its members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reading {
    Testing,
    Ready(u32),
    Failed,
}

impl Reading {
    fn of(probe: &Probe) -> Self {
        match probe {
            Probe::Testing => Reading::Testing,
            Probe::Ready(milliseconds) => Reading::Ready(*milliseconds),
            Probe::Failed(_) => Reading::Failed,
        }
    }

    /// Colored like the tray: green under 200 ms, orange under 500.
    fn value(self, text: Text) -> TileValue {
        match self {
            Reading::Testing => TileValue::Progress,
            Reading::Failed => TileValue::Text {
                text: text.latency_timeout().into(),
                tone: Tone::Danger,
            },
            Reading::Ready(milliseconds) => TileValue::Text {
                text: milliseconds_text(milliseconds),
                tone: milliseconds_tone(milliseconds),
            },
        }
    }
}

/// The profile's nodes and groups by name, its groups' choices and the test
/// results, which a group's latency and member in use come from.
struct Profile<'a> {
    inventory: &'a ProfileInventory,
    nodes: HashMap<&'a str, &'a SavedProxyNode>,
    groups: HashMap<&'a str, &'a SavedPolicyGroup>,
    read: &'a Inventory,
    latency: &'a Latency,
    state: &'a State,
}

impl<'a> Profile<'a> {
    fn new(inventory: &'a Inventory, state: &'a State) -> Self {
        let inventory_ref = &inventory.inventory;
        Self {
            inventory: inventory_ref,
            nodes: inventory_ref
                .proxies
                .iter()
                .map(|node| (node.name.as_str(), node))
                .collect(),
            groups: inventory_ref
                .groups
                .iter()
                .map(|group| (group.name.as_str(), group))
                .collect(),
            read: inventory,
            latency: &state.latency,
            state,
        }
    }

    fn probe(&self, node: &SavedProxyNode) -> Option<&'a Probe> {
        ProbeTarget::of(&self.inventory.profile_id, node)
            .and_then(|target| self.latency.get(&target))
    }

    /// A member's latency: a node's own, a group's as it routes; `visited`
    /// are the groups on the way, which ends a cycle.
    fn member(&self, member: &str, visited: &HashSet<&'a str>) -> Option<Reading> {
        if let Some(node) = self.nodes.get(member) {
            return self.probe(node).map(Reading::of);
        }
        let group = self.groups.get(member)?;
        self.group(group, visited)
    }

    fn group(&self, group: &'a SavedPolicyGroup, visited: &HashSet<&'a str>) -> Option<Reading> {
        if visited.contains(group.name.as_str()) {
            return None;
        }
        let mut visited = visited.clone();
        visited.insert(group.name.as_str());
        if let Some(member) = self.in_use(group) {
            return self.member(member, &visited);
        }
        let readings = group
            .members
            .iter()
            .map(|member| self.member(member, &visited));
        match group.kind.as_str() {
            "fallback" => first_working(readings),
            "relay" => chain(readings),
            _ => fastest(readings),
        }
    }

    /// Whether a member reaches a node that is tested, through its nested
    /// groups too.
    fn reaches_testable(&self, member: &'a str) -> bool {
        let mut stack = vec![member];
        let mut visited = HashSet::new();
        while let Some(member) = stack.pop() {
            if !visited.insert(member) {
                continue;
            }
            if let Some(node) = self.nodes.get(member) {
                if testable(node) {
                    return true;
                }
            } else if let Some(group) = self.groups.get(member) {
                stack.extend(group.members.iter().map(String::as_str));
            }
        }
        false
    }

    fn chosen(&self, group: &'a SavedPolicyGroup) -> Option<&'a str> {
        shown_choice(self.state, &self.read.selections, group)
    }

    fn in_use(&self, group: &'a SavedPolicyGroup) -> Option<&'a str> {
        member_in_use(self.state, self.read, group)
    }
}

/// The fastest working member; otherwise testing, then failed.
fn fastest(readings: impl Iterator<Item = Option<Reading>>) -> Option<Reading> {
    let (mut best, mut testing, mut failed) = (None, false, false);
    for reading in readings.flatten() {
        match reading {
            Reading::Ready(milliseconds) => {
                best = Some(best.map_or(milliseconds, |best: u32| best.min(milliseconds)))
            }
            Reading::Testing => testing = true,
            Reading::Failed => failed = true,
        }
    }
    best.map(Reading::Ready)
        .or(testing.then_some(Reading::Testing))
        .or(failed.then_some(Reading::Failed))
}

/// The first working member in list order; otherwise testing, then failed.
fn first_working(readings: impl Iterator<Item = Option<Reading>>) -> Option<Reading> {
    let (mut testing, mut failed) = (false, false);
    for reading in readings.flatten() {
        match reading {
            Reading::Ready(_) => return Some(reading),
            Reading::Testing => testing = true,
            Reading::Failed => failed = true,
        }
    }
    testing
        .then_some(Reading::Testing)
        .or(failed.then_some(Reading::Failed))
}

/// The hops of a chain added up, once every tested hop works.
fn chain(readings: impl Iterator<Item = Option<Reading>>) -> Option<Reading> {
    let (mut total, mut working, mut testing, mut failed) = (0u32, 0, false, false);
    for reading in readings.flatten() {
        match reading {
            Reading::Ready(milliseconds) => {
                total = total.saturating_add(milliseconds);
                working += 1;
            }
            Reading::Testing => testing = true,
            Reading::Failed => failed = true,
        }
    }
    if testing {
        Some(Reading::Testing)
    } else if failed {
        Some(Reading::Failed)
    } else {
        (working > 0).then_some(Reading::Ready(total))
    }
}

fn tooltip(lines: Vec<String>) -> Option<String> {
    (!lines.is_empty()).then(|| lines.join("\n"))
}

/// A tile that neither is chosen nor takes a press; the entry decides.
fn plain_tile(key: &str, title: &str, kind: String) -> Tile {
    Tile {
        key: key.into(),
        title: title.into(),
        kind,
        detail: None,
        mark: None,
        value: TileValue::None,
        selected: false,
        pressable: false,
        testable: false,
        dimmed: false,
        tooltip: None,
    }
}

fn node_tile(profile: &Profile, node: &SavedProxyNode, text: Text) -> Tile {
    let mut tile = plain_tile(
        &node.name,
        &node.name,
        protocol_label(&node.protocol).into(),
    );
    tile.detail = node.dialer_proxy.as_deref().map(|name| text.via(name));
    tile.mark = node.test_url.is_some().then_some(Icon::Link);
    if let Some(reason) = &node.unsupported {
        tile.value = TileValue::Text {
            text: text.unsupported_badge().into(),
            tone: Tone::Muted,
        };
        tile.dimmed = true;
        tile.tooltip = Some(text.unsupported_hint(reason));
        return tile;
    }
    let probe = profile.probe(node);
    let reading = probe.map(Reading::of);
    if let Some(reading) = reading {
        tile.value = reading.value(text);
    }
    tile.testable = testable(node) && reading != Some(Reading::Testing);
    let mut lines = Vec::new();
    if let Some(url) = &node.test_url {
        lines.push(text.custom_test_url(url));
    }
    if let Some(Probe::Failed(error)) = probe {
        lines.push(text.latency_failed(error));
    }
    tile.tooltip = tooltip(lines);
    tile
}

fn group_tile<'a>(profile: &Profile<'a>, group: &'a SavedPolicyGroup, text: Text) -> Tile {
    let reaches = profile.reaches_testable(group.name.as_str());
    let reading = profile.group(group, &HashSet::new());
    let mut tile = plain_tile(&group.name, &group.name, kind_label(&group.kind).into());
    tile.detail = profile.in_use(group).map(String::from);
    if reaches {
        if let Some(reading) = reading {
            tile.value = reading.value(text);
        }
    }
    tile.testable = reaches && reading != Some(Reading::Testing);
    tile
}

/// A member's tile: a node's, a group's, or a built-in outbound's.
fn member_tile<'a>(profile: &Profile<'a>, member: &'a str, text: Text) -> Tile {
    if let Some(node) = profile.nodes.get(member) {
        return node_tile(profile, node, text);
    }
    if let Some(group) = profile.groups.get(member) {
        return group_tile(profile, group, text);
    }
    plain_tile(member, member, text.builtin_outbound().into())
}

/// The entry's tiles: a choice's members, pressable where they can be
/// chosen unless a change runs long, the chosen one selected.
fn entry_tiles<'a>(
    profile: &Profile<'a>,
    entry: &Entry,
    summary: &'a SavedProfileSummary,
    text: Text,
) -> Vec<Tile> {
    let state = profile.state;
    let waiting = state.transition_slow() || state.downloading_rules();
    let choices = |members: Vec<&'a str>, chosen: Option<&'a str>| -> Vec<Tile> {
        members
            .into_iter()
            .map(|member| {
                let mut tile = member_tile(profile, member, text);
                tile.selected = chosen == Some(member);
                tile.pressable = !tile.selected && !tile.dimmed && !waiting;
                tile
            })
            .collect()
    };
    match entry {
        Entry::Global => {
            let offered = global_outbounds(profile.inventory, state.global_outbound(summary));
            let offered: Vec<&'a str> = offered
                .iter()
                .filter_map(|name| {
                    profile
                        .groups
                        .get_key_value(name.as_str())
                        .map(|(name, _)| *name)
                        .or_else(|| {
                            profile
                                .nodes
                                .get_key_value(name.as_str())
                                .map(|(name, _)| *name)
                        })
                })
                .collect();
            choices(offered, shown_global(state, summary, profile.inventory))
        }
        Entry::Group(id) => {
            let Some(group) = profile
                .inventory
                .groups
                .iter()
                .find(|group| &group.id == id)
            else {
                return Vec::new();
            };
            let members: Vec<&'a str> = group.members.iter().map(String::as_str).collect();
            if group.kind == "select" {
                return choices(members, profile.chosen(group));
            }
            let in_use = profile.in_use(group);
            members
                .into_iter()
                .map(|member| {
                    let mut tile = member_tile(profile, member, text);
                    tile.selected = in_use == Some(member);
                    tile
                })
                .collect()
        }
        Entry::All => listed_nodes(profile.inventory)
            .map(|node| node_tile(profile, node, text))
            .collect(),
    }
}

/// The rail's cards: each entry's name over its kind and what it uses, its
/// latency at the end; the shown one has the accent edge, the others show
/// their entry when pressed.
fn rail_cards<'a>(
    profile: &Profile<'a>,
    summary: &'a SavedProfileSummary,
    mode: TrafficPolicyMode,
    shown: &Entry,
    text: Text,
) -> Vec<Tile> {
    let none = HashSet::new();
    entries(profile.inventory, mode)
        .into_iter()
        .filter_map(|entry| {
            let (title, kind, detail, reading, reaches) = match &entry {
                Entry::Global => {
                    let outbound = shown_global(profile.state, summary, profile.inventory);
                    (
                        text.global_outbound().to_string(),
                        outbound.unwrap_or(text.not_chosen()).to_string(),
                        None,
                        outbound.and_then(|outbound| profile.member(outbound, &none)),
                        outbound.is_some_and(|outbound| profile.reaches_testable(outbound)),
                    )
                }
                Entry::Group(id) => {
                    let group = profile
                        .inventory
                        .groups
                        .iter()
                        .find(|group| &group.id == id)?;
                    (
                        group.name.clone(),
                        kind_label(&group.kind).to_string(),
                        profile.in_use(group).map(String::from),
                        profile.group(group, &none),
                        profile.reaches_testable(group.name.as_str()),
                    )
                }
                Entry::All => return None,
            };
            let selected = entry == *shown;
            let mut card = plain_tile(&entry.key(), &title, kind);
            card.detail = detail;
            if reaches {
                if let Some(reading) = reading {
                    card.value = reading.value(text);
                }
            }
            card.testable = reaches && reading != Some(Reading::Testing);
            card.selected = selected;
            card.pressable = !selected;
            Some(card)
        })
        .collect()
}

fn no_profile_card(title: &str) -> Node {
    card(vec![placeholder(title, None).grow()]).grow()
}

pub fn view(state: &State) -> Node {
    let text = state.text();
    let summary = match &state.active_profile {
        Remote::Ready(Some(profile)) => profile,
        Remote::Ready(None) => return no_profile_card(text.nodes_no_profile()),
        Remote::Loading => return no_profile_card(text.loading()),
        Remote::Failed(_) => return no_profile_card(text.fetch_failed()),
    };
    let page = &state.nodes;
    let Some(inventory) = page
        .inventory
        .ready()
        .filter(|inventory| inventory.inventory.profile_id == summary.id)
    else {
        let title = if matches!(page.inventory, Remote::Failed(_)) {
            text.fetch_failed()
        } else {
            text.loading()
        };
        return no_profile_card(title);
    };
    let mode = state.mode(summary);
    let entry = shown_entry(page.shown.as_deref(), &inventory.inventory, mode);
    let key = MemoKey {
        reads: page.reads,
        latency: state.latency.revision(),
        lang: state.lang,
        entry: entry.clone(),
        mode,
        global: state.global_outbound(summary).map(String::from),
        choosing: match &state.change {
            Some(running) => match &running.change {
                crate::state::Change::Member { group_id, member } => {
                    Some((group_id.clone(), member.clone()))
                }
                _ => None,
            },
            None => None,
        },
        waiting: state.transition_slow() || state.downloading_rules(),
    };
    let (cards, members) = page.built(key, || {
        let profile = Profile::new(inventory, state);
        (
            rail_cards(&profile, summary, mode, &entry, text),
            entry_tiles(&profile, &entry, summary, text),
        )
    });

    let on_press: Box<dyn Fn(String) -> Msg> = match &entry {
        Entry::Global => Box::new(|member| Msg::Nodes(NodesMsg::SetGlobalOutbound(member))),
        Entry::Group(id) => {
            let group_id = id.clone();
            Box::new(move |member| Msg::SelectMember {
                group_id: group_id.clone(),
                member,
            })
        }
        // Nothing is chosen there; its tiles take no press.
        Entry::All => Box::new(|_| Msg::Nodes(NodesMsg::Show(Entry::All.key()))),
    };
    let empty = match &entry {
        Entry::All => text.nodes_empty(),
        _ => text.group_empty(),
    };
    let count = members.len();
    let grid = tiles(Tiles {
        tiles: members,
        min_width: TILE_MIN_WIDTH,
        height: TILE_HEIGHT,
        empty: Some(empty.into()),
        test_label: text.press_to_test().into(),
        check: true,
        on_press: Some(Handler::new(on_press)),
        on_test: Some(Handler::new(|member| {
            Msg::Nodes(NodesMsg::TestMember(member))
        })),
    })
    // A grid of its own for each profile and entry, which starts at the top.
    .key(format!("{}:{}", summary.id, entry.key()))
    .grow();
    let mut parts = vec![column(8.0, vec![caption(text.nodes_caption(count)), grid]).grow()];
    if !cards.is_empty() {
        let rail = tiles(Tiles {
            tiles: cards,
            min_width: RAIL_WIDTH - 20.0,
            height: TILE_HEIGHT,
            empty: None,
            test_label: text.press_to_test().into(),
            check: false,
            on_press: Some(Handler::new(|key| Msg::Nodes(NodesMsg::Show(key)))),
            on_test: Some(Handler::new(|key| Msg::Nodes(NodesMsg::TestEntry(key)))),
        })
        .key(format!("{}:rail", summary.id))
        .grow();
        let groups = text.groups_caption(inventory.inventory.groups.len());
        parts.push(column(8.0, vec![caption(groups), rail]).width(RAIL_WIDTH));
    }
    stack(Axis::Horizontal, 16.0, CrossAlign::Fill, parts).grow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latency::tests::{group, inventory, node};
    use crate::node::Kind;
    use crate::state::{Change, Running};
    use crate::text::Lang;

    fn profile(mode: TrafficPolicyMode, global_outbound: Option<&str>) -> SavedProfileSummary {
        SavedProfileSummary {
            id: "p".into(),
            name: "Profile".into(),
            revision: "1".into(),
            source_revision: "s1".into(),
            traffic_policy_mode: mode,
            global_outbound: global_outbound.map(String::from),
            proxies: 0,
            groups: 0,
            rules: 0,
            updated_at_unix: 0,
        }
    }

    fn state_with(inventory: ProfileInventory, selections: &[(&str, &str)]) -> State {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(Some(profile(TrafficPolicyMode::Rule, None)));
        state.nodes.set_inventory(Remote::Ready(Inventory {
            source_revision: "s1".into(),
            inventory,
            selections: selections
                .iter()
                .map(|(group, member)| ((*group).into(), (*member).into()))
                .collect(),
            automatic: HashMap::new(),
        }));
        state
    }

    /// The members a running Core reports for the automatic groups.
    fn reports(state: &mut State, automatic: &[(&str, &str)]) {
        let chosen = state
            .nodes
            .inventory()
            .ready()
            .expect("an inventory to report against")
            .selections
            .clone();
        state.nodes.set_members(
            "p",
            GroupMembers {
                chosen,
                automatic: automatic
                    .iter()
                    .map(|(group, member)| ((*group).into(), (*member).into()))
                    .collect(),
            },
        );
    }

    fn measure(state: &mut State, name: &str, result: Result<u32, String>) {
        let inventory = &state.nodes.inventory().ready().unwrap().inventory;
        let node = inventory
            .proxies
            .iter()
            .find(|node| node.name == name)
            .unwrap();
        let target = ProbeTarget::of("p", node).unwrap();
        state.latency.request([target.clone()]);
        state.latency.start();
        state.latency.finish(target, result);
    }

    fn start(state: &mut State, name: &str) {
        let inventory = &state.nodes.inventory().ready().unwrap().inventory;
        let node = inventory
            .proxies
            .iter()
            .find(|node| node.name == name)
            .unwrap();
        state.latency.request(ProbeTarget::of("p", node));
    }

    /// The page's parts: the rail's cards and the shown entry's tiles
    /// beside them.
    fn parts(state: &State) -> (Tiles, Tiles) {
        let tree = view(state);
        assert!(matches!(tree.kind, Kind::Stack(_)), "the page is a row");
        let rail = &tree.children[1];
        assert_eq!(rail.attrs.width, Some(RAIL_WIDTH));
        let Kind::Tiles(cards) = &rail.children[1].kind else {
            panic!("the rail holds its cards under its caption");
        };
        (cards.clone(), shown_tiles(state))
    }

    fn shown_tiles(state: &State) -> Tiles {
        let Kind::Tiles(tiles) = &view(state).children[0].children[1].kind else {
            panic!("the page starts with the entry's tiles under their caption");
        };
        tiles.clone()
    }

    /// The captions over the tiles and over the rail.
    fn captions(state: &State) -> Vec<String> {
        view(state)
            .children
            .iter()
            .map(|part| match &part.children[0].kind {
                Kind::Text(caption) => caption.text.clone(),
                _ => panic!("each part starts with its caption"),
            })
            .collect()
    }

    fn value_text(tile: &Tile) -> Option<(&str, Tone)> {
        match &tile.value {
            TileValue::Text { text, tone } => Some((text.as_str(), *tone)),
            _ => None,
        }
    }

    /// A card's title, its second line as drawn, and its value.
    fn card(card: &Tile) -> (&str, String, Option<(&str, Tone)>) {
        let line = match &card.detail {
            Some(detail) => format!("{} · {detail}", card.kind),
            None => card.kind.clone(),
        };
        (card.title.as_str(), line, value_text(card))
    }

    fn shown_entry_key(cards: &Tiles) -> Vec<String> {
        cards
            .tiles
            .iter()
            .filter(|card| card.selected)
            .map(|card| card.key.clone())
            .collect()
    }

    fn show(state: &mut State, entry: Entry) {
        state.nodes.shown = Some(entry.key());
    }

    #[test]
    fn entries_have_keys_that_come_back() {
        for entry in [Entry::Global, Entry::Group("group-a:b".into()), Entry::All] {
            assert_eq!(Entry::from_key(&entry.key()), Some(entry));
        }
        assert_eq!(Entry::from_key("group:"), None);
        assert_eq!(Entry::from_key(""), None);
    }

    #[test]
    fn the_rail_names_the_global_outbound_in_global_mode_then_the_groups() {
        let mut state = state_with(
            inventory(
                vec![node("HK"), node("TW")],
                vec![
                    group("Proxy", "select", &["HK", "TW"]),
                    group("Auto", "url-test", &["HK", "TW"]),
                ],
            ),
            &[("group-Proxy", "TW")],
        );
        let keys = |state: &State| {
            parts(state)
                .0
                .tiles
                .iter()
                .map(|card| card.key.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(keys(&state), ["group:group-Proxy", "group:group-Auto"]);
        assert_eq!(captions(&state), ["Nodes 2", "Groups 2"]);
        let (cards, _) = parts(&state);
        assert!(!cards.check, "the rail shows, it does not check");
        assert_eq!(
            shown_entry_key(&cards),
            ["group:group-Proxy"],
            "the first Select group shows first"
        );
        assert!(!cards.tiles[0].pressable && cards.tiles[1].pressable);
        assert_eq!(card(&cards.tiles[0]).1, "Select · TW");
        let press = cards
            .on_press
            .as_ref()
            .unwrap()
            .call("group:group-Auto".into());
        assert!(matches!(press, Msg::Nodes(NodesMsg::Show(ref key)) if key == "group:group-Auto"));

        state.active_profile = Remote::Ready(Some(profile(TrafficPolicyMode::Global, None)));
        assert_eq!(
            keys(&state),
            ["global", "group:group-Proxy", "group:group-Auto"]
        );
        let (cards, _) = parts(&state);
        assert_eq!(
            shown_entry_key(&cards),
            ["global"],
            "Global mode starts at its outbound"
        );
        assert_eq!(
            card(&cards.tiles[0]).1,
            "Proxy",
            "without a choice the Core uses the first group"
        );
    }

    #[test]
    fn a_chosen_entry_shows_while_the_rail_has_it() {
        let mut state = state_with(
            inventory(
                vec![node("HK")],
                vec![
                    group("Proxy", "select", &["HK"]),
                    group("Auto", "url-test", &["HK"]),
                ],
            ),
            &[],
        );
        show(&mut state, Entry::Group("group-Auto".into()));
        assert_eq!(shown_entry_key(&parts(&state).0), ["group:group-Auto"]);
        show(&mut state, Entry::Global);
        assert_eq!(
            shown_entry_key(&parts(&state).0),
            ["group:group-Proxy"],
            "the global outbound is in the rail only in Global mode"
        );
        show(&mut state, Entry::All);
        assert_eq!(
            shown_entry_key(&parts(&state).0),
            ["group:group-Proxy"],
            "every node is no card of the rail"
        );
    }

    #[test]
    fn a_select_groups_members_are_chosen_by_a_press_and_the_choice_is_marked() {
        let groups = vec![
            group("Proxy", "select", &["HK", "TW", "Auto", "DIRECT", "VMess"]),
            group("Auto", "url-test", &["HK", "TW"]),
        ];
        let mut vmess = node("VMess");
        vmess.unsupported = Some("vmess nodes are not supported yet".into());
        let state = state_with(
            inventory(vec![node("HK"), node("TW"), vmess], groups),
            &[("group-Proxy", "TW")],
        );
        let grid = shown_tiles(&state);
        let tiles: Vec<(&str, bool, bool)> = grid
            .tiles
            .iter()
            .map(|tile| (tile.title.as_str(), tile.selected, tile.pressable))
            .collect();
        assert_eq!(
            tiles,
            [
                ("HK", false, true),
                ("TW", true, false),
                ("Auto", false, true),
                ("DIRECT", false, true),
                ("VMess", false, false),
            ]
        );
        assert_eq!(grid.tiles[2].kind, "URL-Test", "a nested group");
        assert_eq!(grid.tiles[3].kind, "Built-in");
        assert!(grid.tiles[4].dimmed && !grid.tiles[4].testable);
        let press = grid.on_press.as_ref().unwrap().call("HK".into());
        assert!(matches!(
            press,
            Msg::SelectMember { ref group_id, ref member } if group_id == "group-Proxy" && member == "HK"
        ));
    }

    #[test]
    fn a_choice_shows_from_the_click_on_and_a_long_change_takes_no_more_presses() {
        let mut state = state_with(
            inventory(
                vec![node("HK"), node("TW")],
                vec![group("Proxy", "select", &["HK", "TW"])],
            ),
            &[("group-Proxy", "TW")],
        );
        state.change = Some(Running {
            change: Change::Member {
                group_id: "group-Proxy".into(),
                member: "HK".into(),
            },
            id: 1,
            slow: false,
        });
        let grid = shown_tiles(&state);
        assert!(grid.tiles[0].selected && !grid.tiles[1].selected);
        assert!(grid.tiles[1].pressable, "a quick change dims nothing");
        assert_eq!(card(&parts(&state).0.tiles[0]).1, "Select · HK");
        state.change.as_mut().unwrap().slow = true;
        assert!(shown_tiles(&state).tiles.iter().all(|tile| !tile.pressable));
    }

    #[test]
    fn an_automatic_groups_members_are_listed_not_chosen() {
        let mut state = state_with(
            inventory(
                vec![node("HK"), node("TW")],
                vec![group("Auto", "url-test", &["HK", "TW"])],
            ),
            &[],
        );
        show(&mut state, Entry::Group("group-Auto".into()));
        let grid = shown_tiles(&state);
        assert!(grid
            .tiles
            .iter()
            .all(|tile| !tile.pressable && !tile.selected && tile.testable));
    }

    #[test]
    fn the_global_outbound_is_chosen_from_the_groups_and_usable_nodes() {
        let mut vmess = node("VMess");
        vmess.unsupported = Some("no".into());
        let mut state = state_with(
            inventory(
                vec![node("HK"), vmess],
                vec![group("Proxy", "select", &["HK"])],
            ),
            &[],
        );
        state.active_profile = Remote::Ready(Some(profile(TrafficPolicyMode::Global, Some("HK"))));
        let grid = shown_tiles(&state);
        let tiles: Vec<(&str, bool)> = grid
            .tiles
            .iter()
            .map(|tile| (tile.title.as_str(), tile.selected))
            .collect();
        assert_eq!(tiles, [("Proxy", false), ("HK", true)]);
        let press = grid.on_press.as_ref().unwrap().call("Proxy".into());
        assert!(matches!(
            press,
            Msg::Nodes(NodesMsg::SetGlobalOutbound(ref name)) if name == "Proxy"
        ));
        state.change = Some(Running {
            change: Change::GlobalOutbound("Proxy".into()),
            id: 1,
            slow: false,
        });
        assert!(
            shown_tiles(&state).tiles[0].selected,
            "the outbound shows from the click on"
        );
    }

    #[test]
    fn global_outbounds_list_groups_then_usable_nodes_and_keep_the_saved_one() {
        let mut vmess = node("VMess");
        vmess.unsupported = Some("no".into());
        let inventory = inventory(
            vec![node("HK"), vmess],
            vec![group("Proxy", "select", &["HK"])],
        );
        assert_eq!(global_outbounds(&inventory, None), ["Proxy", "HK"]);
        assert_eq!(
            global_outbounds(&inventory, Some("Gone")),
            ["Proxy", "HK", "Gone"]
        );
        assert_eq!(global_outbounds(&inventory, Some("HK")), ["Proxy", "HK"]);
    }

    #[test]
    fn every_node_lists_all_but_hidden_ones_with_their_dialer_and_test_url() {
        let mut hidden = node("Hidden");
        hidden.hidden = true;
        let mut chained = node("Chained");
        chained.dialer_proxy = Some("Relay".into());
        chained.test_url = Some("https://example.com/204".into());
        let mut vmess = node("VMess");
        vmess.protocol = "vmess".into();
        vmess.unsupported = Some("vmess nodes are not supported yet".into());
        let state = state_with(
            inventory(vec![node("HK"), hidden, chained, vmess], Vec::new()),
            &[],
        );
        assert_eq!(
            captions(&state),
            ["Nodes 3"],
            "without groups the page is every node, with no rail"
        );
        let grid = shown_tiles(&state);
        let titles: Vec<_> = grid.tiles.iter().map(|tile| tile.title.as_str()).collect();
        assert_eq!(titles, ["HK", "Chained", "VMess"]);
        assert!(
            Rc::ptr_eq(&shown_tiles(&state).tiles, &shown_tiles(&state).tiles),
            "an unchanged page reuses its tiles"
        );
        let tiles = &grid.tiles;
        assert_eq!(tiles[0].kind, "Trojan");
        assert_eq!(tiles[0].value, TileValue::None, "untested");
        assert!(tiles[0].testable && !tiles[0].pressable && !tiles[0].selected);
        assert_eq!(tiles[1].detail.as_deref(), Some("via Relay"));
        assert_eq!(tiles[1].mark, Some(Icon::Link));
        assert!(tiles[1]
            .tooltip
            .as_deref()
            .is_some_and(|tooltip| tooltip.contains("https://example.com/204")));
        assert!(tiles[2].dimmed && !tiles[2].testable);
        assert_eq!(value_text(&tiles[2]), Some(("Unsupported", Tone::Muted)));
        assert!(tiles[2]
            .tooltip
            .as_deref()
            .is_some_and(|tooltip| tooltip.contains("vmess nodes are not supported yet")));
        let test = grid.on_test.as_ref().unwrap().call("HK".into());
        assert!(matches!(test, Msg::Nodes(NodesMsg::TestMember(ref name)) if name == "HK"));
    }

    #[test]
    fn latencies_take_the_trays_colors_and_a_running_test_takes_no_second() {
        let names = ["A", "B", "C", "D", "E", "F"];
        let mut state = state_with(
            inventory(names.iter().map(|name| node(name)).collect(), Vec::new()),
            &[],
        );
        measure(&mut state, "A", Ok(0));
        measure(&mut state, "B", Ok(199));
        measure(&mut state, "C", Ok(200));
        measure(&mut state, "D", Ok(500));
        measure(&mut state, "E", Err("timed out".into()));
        start(&mut state, "F");
        let grid = shown_tiles(&state);
        let tiles = &grid.tiles;
        assert_eq!(value_text(&tiles[0]), Some(("<1 ms", Tone::Success)));
        assert_eq!(value_text(&tiles[1]), Some(("199 ms", Tone::Success)));
        assert_eq!(value_text(&tiles[2]), Some(("200 ms", Tone::Warning)));
        assert_eq!(value_text(&tiles[3]), Some(("500 ms", Tone::Danger)));
        assert_eq!(value_text(&tiles[4]), Some(("Timeout", Tone::Danger)));
        assert!(tiles[4]
            .tooltip
            .as_deref()
            .is_some_and(|tooltip| tooltip.contains("timed out")));
        assert_eq!(tiles[5].value, TileValue::Progress);
        assert!(!tiles[5].testable);
    }

    #[test]
    fn a_group_shows_the_member_it_uses_and_its_latency() {
        let groups = vec![
            group("Proxy", "select", &["Auto", "HK"]),
            group("Auto", "url-test", &["HK", "TW"]),
            group("Backup", "fallback", &["HK", "TW"]),
            group("Chain", "relay", &["HK", "TW"]),
            group("Local", "select", &["DIRECT"]),
        ];
        let mut state = state_with(
            inventory(vec![node("HK"), node("TW")], groups),
            &[("group-Proxy", "HK")],
        );
        measure(&mut state, "HK", Err("refused".into()));
        measure(&mut state, "TW", Ok(120));

        // Without a Core nothing dials through an automatic group, so it
        // names no member; its card still reads over the members.
        let (cards, _) = parts(&state);
        assert_eq!(card(&cards.tiles[1]).1, "URL-Test");
        assert_eq!(card(&cards.tiles[2]).1, "Fallback");

        reports(&mut state, &[("group-Auto", "TW"), ("group-Backup", "TW")]);
        let (cards, _) = parts(&state);
        let rows: Vec<(String, Option<(&str, Tone)>)> = cards
            .tiles
            .iter()
            .map(|tile| {
                let (_, line, value) = card(tile);
                (line, value)
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("Select · HK".to_string(), Some(("Timeout", Tone::Danger))),
                ("URL-Test · TW".to_string(), Some(("120 ms", Tone::Success))),
                ("Fallback · TW".to_string(), Some(("120 ms", Tone::Success))),
                ("Relay".to_string(), Some(("Timeout", Tone::Danger))),
                ("Select · DIRECT".to_string(), None),
            ]
        );
        assert!(!cards.tiles[4].testable, "DIRECT has nothing to test");
        let test = cards
            .on_test
            .as_ref()
            .unwrap()
            .call("group:group-Auto".into());
        assert!(
            matches!(test, Msg::Nodes(NodesMsg::TestEntry(ref key)) if key == "group:group-Auto")
        );
        show(&mut state, Entry::Group("group-Proxy".into()));
        let grid = shown_tiles(&state);
        assert_eq!(grid.tiles[0].detail.as_deref(), Some("TW"), "Auto uses TW");
        assert_eq!(value_text(&grid.tiles[0]), Some(("120 ms", Tone::Success)));

        // A report naming a member this profile's group no longer has
        // (the Core still serves the one before an edit) names none.
        reports(&mut state, &[("group-Auto", "Gone")]);
        let (cards, _) = parts(&state);
        assert_eq!(card(&cards.tiles[1]).1, "URL-Test");
        reports(&mut state, &[("group-Auto", "TW"), ("group-Backup", "TW")]);

        // The member in use is marked where the members are listed, and
        // none of them can be chosen.
        show(&mut state, Entry::Group("group-Auto".into()));
        let grid = shown_tiles(&state);
        let marks: Vec<(&str, bool, bool)> = grid
            .tiles
            .iter()
            .map(|tile| (tile.title.as_str(), tile.selected, tile.pressable))
            .collect();
        assert_eq!(marks, [("HK", false, false), ("TW", true, false)]);
    }

    #[test]
    fn a_select_group_follows_a_nested_groups_latency_and_a_cycle_ends() {
        let groups = vec![
            group("Proxy", "select", &["Auto"]),
            group("Auto", "url-test", &["HK", "Proxy"]),
        ];
        let mut state = state_with(inventory(vec![node("HK")], groups), &[]);
        measure(&mut state, "HK", Ok(80));
        let (cards, _) = parts(&state);
        assert_eq!(card(&cards.tiles[0]).1, "Select · Auto");
        assert_eq!(card(&cards.tiles[0]).2, Some(("80 ms", Tone::Success)));
        assert_eq!(card(&cards.tiles[1]).2, Some(("80 ms", Tone::Success)));
    }

    #[test]
    fn testing_asks_for_the_entry_or_the_member() {
        let groups = vec![
            group("Proxy", "select", &["Auto", "HK"]),
            group("Auto", "url-test", &["TW"]),
        ];
        let inventory = inventory(vec![node("HK"), node("TW"), node("JP")], groups);
        let names = |targets: Vec<ProbeTarget>| {
            targets
                .into_iter()
                .map(|target| target.node)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(entry_targets(
                &inventory,
                &Entry::Group("group-Proxy".into())
            )),
            ["TW", "HK"]
        );
        assert_eq!(
            names(entry_targets(&inventory, &Entry::All)),
            ["HK", "TW", "JP"]
        );
        assert_eq!(names(member_targets(&inventory, "JP")), ["JP"]);
        assert_eq!(names(member_targets(&inventory, "Auto")), ["TW"]);
        assert!(member_targets(&inventory, "DIRECT").is_empty());
    }

    #[test]
    fn without_a_profile_the_page_says_so() {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(None);
        let tree = view(&state);
        assert!(matches!(tree.kind, Kind::Card(_)));
        assert!(matches!(tree.children[0].kind, Kind::Placeholder(_)));
    }

    #[test]
    fn each_profile_and_entry_gets_a_grid_of_its_own() {
        let mut state = state_with(
            inventory(
                vec![node("HK")],
                vec![
                    group("Proxy", "select", &["HK"]),
                    group("Auto", "url-test", &["HK"]),
                ],
            ),
            &[],
        );
        let key = |state: &State| view(state).children[0].children[1].key.clone();
        assert_eq!(key(&state).as_deref(), Some("p:group:group-Proxy"));
        show(&mut state, Entry::Group("group-Auto".into()));
        assert_eq!(key(&state).as_deref(), Some("p:group:group-Auto"));
    }
}
