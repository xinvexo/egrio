//! The rules page: the active profile's rules in one table filling the page:
//! the type, the content (for a rule set its link and how many entries it
//! has), the outbound, and how many connections the rule matched since the
//! app started. A filter narrows the table; double-clicking a rule edits it
//! in a dialog; with no filter, dragging rows reorders the rules; the
//! selected rules can be deleted. The toolbar tests where a destination
//! would go, updates the rule sets and resets the counts.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use egrio_core::{
    NativeCoreState, RouteEvaluation, RouteMatchKind, RouteRule, RuleKind, TrafficPolicyMode,
};
use egrio_desktop::models::ProfileRuleList;
use egrio_desktop::profile_store::{ProfileInventory, SavedRuleProvider};

use crate::format;
use crate::msg::{Msg, RulesMsg};
use crate::node::{
    badge, button, caption, card, column, heading, icon_button, paragraph, placeholder, popover,
    row, search_field, select, spacer, switch, table, text_field, ButtonKey, ButtonStyle, Cell,
    Column, ColumnAlign, ColumnWidth, Handler, Icon, Node, Row, Selection, Table, TextStyle, Tone,
};
use crate::state::{Remote, State};
use crate::text::{Lang, Text};

/// The rule types a new rule can have, those the Core matches; MATCH takes
/// no content. A rule of another type keeps its type when edited.
pub const RULE_KINDS: [&str; 18] = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "GEOIP",
    "RULE-SET",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "DST-PORT",
    "SRC-PORT",
    "NETWORK",
    "AND",
    "OR",
    "NOT",
    "MATCH",
];

/// Types whose match may first resolve a name to an address, which
/// `no-resolve` skips.
fn takes_no_resolve(kind: &str) -> bool {
    matches!(kind, "GEOIP" | "IP-CIDR" | "IP-CIDR6" | "RULE-SET")
}

/// Common GEOIP country codes.
const COUNTRIES: [&str; 14] = [
    "CN", "US", "JP", "KR", "HK", "TW", "SG", "RU", "GB", "DE", "FR", "NL", "AU", "CA",
];

const NETWORKS: [&str; 2] = ["tcp", "udp"];

/// What the page keeps: the active profile's rules as last read, the
/// filter, the selection, the counts and the route test, and the rows built
/// for the last render, reused while nothing they show changed.
#[derive(Debug)]
pub struct RulesPage {
    list: Remote<ProfileRuleList>,
    /// The places of the list's rules in the order shown while a reorder
    /// is being saved; the file's order otherwise.
    order: Option<Vec<usize>>,
    /// Counts the reads and the changes made in place, which tells the memo
    /// the list changed.
    revision: u64,
    pub filter: String,
    /// The selected rules' ids.
    pub selected: Vec<String>,
    /// Connections matched, by the rule as written, for the listed profile.
    hits: HashMap<String, u64>,
    hits_revision: u64,
    /// A change to the rules is being saved: deleting or reordering.
    pub saving: bool,
    pub refreshing: bool,
    pub route: RouteTest,
    memo: RefCell<Option<(MemoKey, Rc<Vec<Rc<Row>>>)>>,
}

#[derive(Debug, Clone, PartialEq)]
struct MemoKey {
    revision: u64,
    hits: u64,
    filter: String,
    lang: Lang,
}

/// The route test's panel: what to test, whether a test runs, and the last
/// one, kept until the next.
#[derive(Debug, Clone)]
pub struct RouteTest {
    pub target: String,
    pub running: bool,
    pub result: Option<(String, Result<RouteEvaluation, String>)>,
}

impl Default for RulesPage {
    fn default() -> Self {
        Self {
            list: Remote::Loading,
            order: None,
            revision: 0,
            filter: String::new(),
            selected: Vec::new(),
            hits: HashMap::new(),
            hits_revision: 0,
            saving: false,
            refreshing: false,
            route: RouteTest {
                target: "google.com".into(),
                running: false,
                result: None,
            },
            memo: RefCell::new(None),
        }
    }
}

impl RulesPage {
    /// Gives back the rows built for the last render; the next builds them.
    pub fn forget_rows(&mut self) {
        *self.memo.get_mut() = None;
    }

    pub fn list(&self) -> &Remote<ProfileRuleList> {
        &self.list
    }

    /// The list for `profile_id`, if that is the one read.
    pub fn list_for(&self, profile_id: &str) -> Option<&ProfileRuleList> {
        self.list
            .ready()
            .filter(|list| list.profile_id == profile_id)
    }

    /// A new read of the rules. A rule's id is its place in one version of
    /// the file, so a selection made in another version is dropped.
    pub fn set_list(&mut self, list: Remote<ProfileRuleList>) {
        let same_source = match (self.list.ready(), list.ready()) {
            (Some(old), Some(new)) => {
                old.profile_id == new.profile_id && old.source_revision == new.source_revision
            }
            _ => false,
        };
        if !same_source {
            self.selected.clear();
        }
        self.list = list;
        self.order = None;
        self.revision += 1;
    }

    /// Shows the rules in their new order while the change is saved: the
    /// rows keep the ids of the file the page still holds.
    pub fn reorder(&mut self, order: &[String]) {
        if let Remote::Ready(list) = &self.list {
            self.order = Some(order.iter().filter_map(|id| list.place(id)).collect());
            self.revision += 1;
        }
    }

    pub fn set_hits(&mut self, hits: HashMap<String, u64>) {
        if hits != self.hits {
            self.hits = hits;
            self.hits_revision += 1;
        }
    }

    pub fn has_hits(&self) -> bool {
        self.hits.values().any(|count| *count > 0)
    }
}

/// The dialog's draft of a new rule or of a change to one.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleDraft {
    pub profile_id: String,
    /// The version of the file the draft is based on.
    pub source_revision: String,
    /// The rule changed, `None` for a new one.
    pub rule_id: Option<String>,
    /// Written in capitals, as Clash configurations do.
    pub kind: String,
    pub payload: String,
    pub outbound: String,
    pub no_resolve: bool,
    /// Its save is running.
    pub pending: bool,
    /// Why its last save failed, which the dialog shows until the next one.
    pub error: Option<String>,
}

impl RuleDraft {
    pub fn new(list: &ProfileRuleList) -> Self {
        Self {
            profile_id: list.profile_id.clone(),
            source_revision: list.source_revision.clone(),
            rule_id: None,
            kind: "DOMAIN-SUFFIX".into(),
            payload: String::new(),
            outbound: "DIRECT".into(),
            no_resolve: false,
            pending: false,
            error: None,
        }
    }

    /// A change to the rule at `place` of the list, if it has one there.
    pub fn edit(list: &ProfileRuleList, place: usize) -> Option<Self> {
        let rule = list.rules.get(place)?;
        Some(Self {
            profile_id: list.profile_id.clone(),
            source_revision: list.source_revision.clone(),
            rule_id: Some(ProfileRuleList::rule_id(place)),
            kind: list.kind(place)?,
            payload: rule.payload.unwrap_or_default().into(),
            outbound: rule.outbound.into(),
            no_resolve: rule.no_resolve,
            pending: false,
            error: None,
        })
    }

    /// Another type: what was written for the old one means nothing for the
    /// new one, so a choice starts at its first option and text starts empty.
    pub fn set_kind(&mut self, kind: &str, providers: &[String]) {
        if self.kind == kind {
            return;
        }
        self.kind = kind.into();
        self.no_resolve = false;
        self.payload = match kind {
            "GEOIP" => COUNTRIES[0].into(),
            "NETWORK" => NETWORKS[0].into(),
            "RULE-SET" => providers.first().cloned().unwrap_or_default(),
            _ => String::new(),
        };
    }

    pub fn can_save(&self, providers: &[String]) -> bool {
        let payload = self.payload.trim();
        !self.pending
            && !self.outbound.trim().is_empty()
            && match self.kind.as_str() {
                "MATCH" => true,
                "RULE-SET" => providers.iter().any(|name| name == payload),
                _ => !payload.is_empty(),
            }
    }

    /// The content as saved: none for MATCH.
    pub fn saved_payload(&self) -> Option<String> {
        let payload = self.payload.trim();
        (self.kind != "MATCH" && !payload.is_empty()).then(|| payload.to_string())
    }
}

/// The rule sets a RULE-SET rule can name: those the file defines.
pub fn provider_names(list: &ProfileRuleList) -> Vec<String> {
    list.rule_providers
        .iter()
        .map(|provider| provider.name.clone())
        .collect()
}

/// What a rule can send traffic to: DIRECT and REJECT, the groups, then the
/// nodes, each once.
pub fn outbounds(inventory: Option<&ProfileInventory>) -> Vec<String> {
    let mut names = vec!["DIRECT".to_string(), "REJECT".to_string()];
    if let Some(inventory) = inventory {
        let more = inventory
            .groups
            .iter()
            .map(|group| &group.name)
            .chain(inventory.proxies.iter().map(|node| &node.name));
        for name in more {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    names
}

/// A rule's outbound in the color that tells what it does: muted for
/// DIRECT, red for REJECT, the accent for a proxy.
pub fn outbound_tone(outbound: &str) -> Tone {
    match outbound.trim().to_ascii_uppercase().as_str() {
        "DIRECT" => Tone::Muted,
        "REJECT" | "REJECT-DROP" | "BLOCK" => Tone::Danger,
        _ => Tone::Accent,
    }
}

fn provider_for<'a>(
    rule: &RouteRule<'_>,
    providers: &'a HashMap<&str, &SavedRuleProvider>,
) -> Option<&'a SavedRuleProvider> {
    (rule.kind == RuleKind::RuleSet)
        .then(|| providers.get(rule.payload.unwrap_or_default()).copied())
        .flatten()
}

/// Every word is in the rule's type, content, rule set link or outbound.
fn matches(
    kind: &str,
    rule: &RouteRule<'_>,
    provider: Option<&SavedRuleProvider>,
    terms: &[String],
) -> bool {
    // Without a filter every rule shows, and nothing is put together to
    // search.
    if terms.is_empty() {
        return true;
    }
    let haystack = [
        Some(kind),
        rule.payload,
        provider.and_then(|provider| provider.url.as_deref()),
        Some(rule.outbound),
    ]
    .into_iter()
    .flatten()
    .map(str::to_lowercase)
    .collect::<Vec<_>>()
    .join("\n");
    terms.iter().all(|term| haystack.contains(term.as_str()))
}

/// One listed rule's row: `kind` is its type as the page shows it.
fn rule_row(
    key: String,
    kind: String,
    rule: &RouteRule<'_>,
    provider: Option<&SavedRuleProvider>,
    hits: u64,
    unsupported: bool,
    text: Text,
) -> Row {
    let mut content = Vec::new();
    match provider {
        Some(provider) => {
            content.push(Cell::Text {
                text: provider
                    .url
                    .clone()
                    .unwrap_or_else(|| text.local_rule_set().into()),
                tone: Tone::Default,
                mono: true,
            });
            content.push(match provider.fetched_at_unix {
                Some(_) => Cell::Badge {
                    text: text.entry_count(provider.entry_count.unwrap_or(0)),
                    tone: Tone::Success,
                },
                None => Cell::Badge {
                    text: text.not_fetched().into(),
                    tone: Tone::Warning,
                },
            });
        }
        None => content.push(Cell::Text {
            text: rule.payload.unwrap_or("*").into(),
            tone: Tone::Default,
            mono: true,
        }),
    }
    if rule.no_resolve {
        content.push(Cell::Badge {
            text: "no-resolve".into(),
            tone: Tone::Muted,
        });
    }
    // The Core leaves the rule out: its type is not one it implements, or
    // its content is not what the type reads.
    if unsupported {
        content.push(Cell::Badge {
            text: text.unsupported_badge().into(),
            tone: Tone::Warning,
        });
    }
    Row {
        key,
        cells: vec![
            Cell::Text {
                text: kind,
                tone: Tone::Muted,
                mono: true,
            },
            Cell::Inline(content),
            Cell::Badge {
                text: rule.outbound.into(),
                tone: outbound_tone(rule.outbound),
            },
            Cell::Number(hits.to_string()),
        ],
    }
}

/// The rows of the rules the filter lets through, in the file's order.
fn rows(page: &RulesPage, list: &ProfileRuleList, lang: Lang) -> Rc<Vec<Rc<Row>>> {
    let key = MemoKey {
        revision: page.revision,
        hits: page.hits_revision,
        filter: page.filter.clone(),
        lang,
    };
    if let Some((cached, rows)) = page.memo.borrow().as_ref() {
        if *cached == key {
            return rows.clone();
        }
    }
    let providers: HashMap<&str, &SavedRuleProvider> = list
        .rule_providers
        .iter()
        .map(|provider| (provider.name.as_str(), provider))
        .collect();
    let terms = format::search_terms(&page.filter);
    let text = Text(lang);
    let row = |place: usize| {
        let rule = list.rules.get(place)?;
        let kind = list.kind(place)?;
        let provider = provider_for(&rule, &providers);
        if !matches(&kind, &rule, provider, &terms) {
            return None;
        }
        // The Core names the rule a connection matched as the profile
        // writes it, and so the hits are counted: a rule's id is only its
        // place in this version of the file, and a rule added ahead of it
        // would hand its count to another rule.
        let hits = match page.hits.is_empty() {
            true => 0,
            false => page.hits.get(&rule.text()).copied().unwrap_or(0),
        };
        Some(Rc::new(rule_row(
            ProfileRuleList::rule_id(place),
            kind,
            &rule,
            provider,
            hits,
            list.unsupported.contains_key(&place),
            text,
        )))
    };
    let rows: Rc<Vec<Rc<Row>>> = Rc::new(match &page.order {
        Some(order) => order.iter().copied().filter_map(row).collect(),
        None => (0..list.rules.len()).filter_map(row).collect(),
    });
    *page.memo.borrow_mut() = Some((key, rows.clone()));
    rows
}

/// The selected rules among `rows`. Every rule may be selected, so the
/// rows are looked up, not searched for each one.
fn selected_among(page: &RulesPage, rows: &[Rc<Row>]) -> Vec<String> {
    if page.selected.is_empty() {
        return Vec::new();
    }
    let listed: HashSet<&str> = rows.iter().map(|row| row.key.as_str()).collect();
    page.selected
        .iter()
        .filter(|id| listed.contains(id.as_str()))
        .cloned()
        .collect()
}

/// The selected rules of the active profile that the filter lets through:
/// what the page counts as selected, and so what deleting removes. A rule
/// selected before a filter hid it is not among them.
pub fn shown_selection(state: &State) -> Vec<String> {
    let page = &state.rules;
    let list = state
        .active_profile
        .ready()
        .and_then(Option::as_ref)
        .and_then(|profile| page.list_for(&profile.id));
    match list {
        Some(list) => selected_among(page, &rows(page, list, state.lang)),
        None => Vec::new(),
    }
}

fn columns(text: Text) -> Vec<Column> {
    let column = |title: &str, width, align| Column {
        title: title.into(),
        width,
        align,
        sortable: false,
    };
    vec![
        column(
            text.col_kind(),
            ColumnWidth::Fixed(124.0),
            ColumnAlign::Leading,
        ),
        column(
            text.col_payload(),
            ColumnWidth::Flexible { min: 200.0 },
            ColumnAlign::Leading,
        ),
        column(
            text.col_outbound(),
            ColumnWidth::Fixed(132.0),
            ColumnAlign::Leading,
        ),
        column(
            text.col_hits(),
            ColumnWidth::Fixed(64.0),
            ColumnAlign::Trailing,
        ),
    ]
}

/// The route test's panel: a field and its button, then where the last
/// test went and by which rule, or why it failed.
fn route_test(state: &State, profile_running: bool) -> Node {
    let text = state.text();
    let test = &state.rules.route;
    let mut children = vec![row(
        8.0,
        vec![
            text_field(
                test.target.clone(),
                text.route_target_placeholder(),
                true,
                |target| Msg::Rules(RulesMsg::RouteTarget(target)),
            )
            .grow(),
            button(text.run_test(), ButtonStyle::Primary)
                .key(ButtonKey::Return)
                .busy(test.running)
                .enabled(!test.target.trim().is_empty())
                .on_press(Msg::Rules(RulesMsg::TestRoute)),
        ],
    )];
    match &test.result {
        Some((_, Err(error))) => {
            children.push(paragraph(text.route_test_failed(error), Tone::Danger));
        }
        Some((target, Ok(evaluation))) => {
            let decision = &evaluation.decision;
            let rule = match (decision.matched_kind, decision.traffic_policy_mode) {
                (Some(kind), _) => match_kind_label(kind),
                (None, TrafficPolicyMode::Rule) => "MATCH",
                (None, TrafficPolicyMode::Global) => "GLOBAL",
                (None, TrafficPolicyMode::Direct) => "DIRECT",
            };
            let detail: Vec<String> = [
                Some(rule.to_string()),
                decision.matched_payload.clone(),
                evaluation.resolved_ip.map(|ip| ip.to_string()),
            ]
            .into_iter()
            .flatten()
            .collect();
            children.push(row(
                8.0,
                vec![
                    crate::node::text(target.clone(), TextStyle::Mono, Tone::Default),
                    caption("→"),
                    badge(
                        evaluation.resolved_outbound.clone(),
                        outbound_tone(&evaluation.resolved_outbound),
                    ),
                    spacer(),
                ],
            ));
            children.push(caption(detail.join(" · ")));
        }
        // A Core that isn't running answers from the saved profile.
        None if !profile_running => children.push(caption(text.route_test_saved())),
        None => {}
    }
    column(10.0, children).width(340.0)
}

/// The rule types as Clash spells them.
pub fn match_kind_label(kind: RouteMatchKind) -> &'static str {
    match kind {
        RouteMatchKind::Domain => "DOMAIN",
        RouteMatchKind::DomainSuffix => "DOMAIN-SUFFIX",
        RouteMatchKind::DomainKeyword => "DOMAIN-KEYWORD",
        RouteMatchKind::DomainRegex => "DOMAIN-REGEX",
        RouteMatchKind::GeoIp => "GEOIP",
        RouteMatchKind::GeoSite => "GEOSITE",
        RouteMatchKind::IpCidr => "IP-CIDR",
        RouteMatchKind::SrcIpCidr => "SRC-IP-CIDR",
        RouteMatchKind::DstPort => "DST-PORT",
        RouteMatchKind::SrcPort => "SRC-PORT",
        RouteMatchKind::ProcessName => "PROCESS-NAME",
        RouteMatchKind::ProcessPath => "PROCESS-PATH",
        RouteMatchKind::Network => "NETWORK",
        RouteMatchKind::And => "AND",
        RouteMatchKind::Or => "OR",
        RouteMatchKind::Not => "NOT",
        RouteMatchKind::RuleSet => "RULE-SET",
        RouteMatchKind::Match => "MATCH",
    }
}

pub fn view(state: &State) -> Node {
    let text = state.text();
    let profile = match &state.active_profile {
        Remote::Ready(Some(profile)) => profile,
        Remote::Ready(None) => {
            return card(vec![placeholder(text.nodes_no_profile(), None).grow()]).grow()
        }
        Remote::Loading => return card(vec![placeholder(text.loading(), None).grow()]).grow(),
        Remote::Failed(_) => {
            return card(vec![placeholder(text.fetch_failed(), None).grow()]).grow()
        }
    };
    let page = &state.rules;
    let list = page.list_for(&profile.id);
    let filtering = !page.filter.trim().is_empty();
    let (rows, empty) = match list {
        Some(list) => (
            rows(page, list, state.lang),
            if filtering {
                text.rules_no_match()
            } else {
                text.rules_empty()
            },
        ),
        None if matches!(page.list, Remote::Failed(_)) => (Rc::default(), text.fetch_failed()),
        None => (Rc::default(), text.loading()),
    };
    let total = list.map_or(0, |list| list.rules.len());
    let shown = selected_among(page, &rows);
    let count = if shown.is_empty() {
        text.rule_count(total)
    } else {
        text.rules_selected(shown.len(), total)
    };
    let idle = list.is_some() && !page.saving;
    let remote_providers = list.is_some_and(|list| {
        list.rule_providers
            .iter()
            .any(|provider| provider.url.is_some())
    });
    // The Core runs only the active profile.
    let profile_running = state
        .core
        .as_ref()
        .is_some_and(|core| core.state == NativeCoreState::Running);
    let toolbar = row(
        8.0,
        vec![
            search_field(page.filter.clone(), text.rules_filter(), |filter| {
                Msg::Rules(RulesMsg::Filter(filter))
            }),
            badge(count, Tone::Muted),
            spacer(),
            popover(
                text.test_route(),
                Some(Icon::Route),
                true,
                route_test(state, profile_running),
            ),
            icon_button(Icon::Refresh)
                .enabled(remote_providers)
                .busy(page.refreshing)
                .on_press(Msg::Rules(RulesMsg::RefreshProviders))
                .tooltip(Some(
                    if remote_providers {
                        text.refresh_providers()
                    } else {
                        text.no_remote_providers()
                    }
                    .into(),
                )),
            icon_button(Icon::ResetCount)
                .enabled(page.has_hits())
                .on_press(Msg::Rules(RulesMsg::ResetHits))
                .tooltip(Some(text.reset_hits().into())),
            icon_button(Icon::Add)
                .enabled(idle)
                .on_press(Msg::Rules(RulesMsg::Add))
                .tooltip(Some(text.add_rule().into())),
            icon_button(Icon::Delete)
                .enabled(idle && !shown.is_empty())
                .busy(page.saving)
                .on_press(Msg::Rules(RulesMsg::Delete))
                .tooltip(Some(if shown.is_empty() {
                    text.delete().into()
                } else {
                    text.delete_rules(shown.len())
                })),
        ],
    );
    // Reordering a part of the list would be ambiguous, so only the whole
    // list moves.
    let movable = idle && !filtering;
    let rules = table(Table {
        columns: columns(text),
        rows,
        header: true,
        row_height: 32.0,
        selection: Selection::Multiple,
        selected: shown,
        sort: None,
        empty: Some(empty.into()),
        follow_end: false,
        wrap: false,
        on_select: Some(Handler::new(|keys| Msg::Rules(RulesMsg::Select(keys)))),
        on_activate: Some(Handler::new(|key| Msg::Rules(RulesMsg::Edit(key)))),
        on_sort: None,
        on_move: movable.then(|| {
            Handler::new(|(keys, to): (Vec<String>, usize)| Msg::Rules(RulesMsg::Move { keys, to }))
        }),
    })
    .grow()
    .key(format!("rules:{}", profile.id));
    card(vec![toolbar, rules]).grow()
}

fn labelled(label: &str, control: Node) -> Node {
    column(6.0, vec![caption(label), control])
}

/// The dialog for a new rule or a change to one. Its fields keep their
/// places for every type: the content field changes its control, and
/// no-resolve waits for a type that resolves names.
pub fn dialog(state: &State, draft: &RuleDraft) -> Node {
    let text = state.text();
    let list = state.rules.list_for(&draft.profile_id);
    let providers = list.map(provider_names).unwrap_or_default();
    let open = !draft.pending;
    let mut kinds: Vec<String> = RULE_KINDS.iter().map(|kind| (*kind).to_string()).collect();
    if !kinds.contains(&draft.kind) {
        kinds.insert(0, draft.kind.clone());
    }
    let kind_index = kinds.iter().position(|kind| *kind == draft.kind);
    let kind_names = kinds.clone();
    let kind = select(kinds, kind_index, open, move |index| {
        Msg::Rules(RulesMsg::DraftKind(
            kind_names.get(index).cloned().unwrap_or_default(),
        ))
    });
    let choice = |options: Vec<String>, enabled: bool| {
        let mut options = options;
        if !draft.payload.is_empty() && !options.contains(&draft.payload) {
            options.insert(0, draft.payload.clone());
        }
        let selected = options.iter().position(|option| *option == draft.payload);
        let names = options.clone();
        select(options, selected, enabled && open, move |index| {
            Msg::Rules(RulesMsg::DraftPayload(
                names.get(index).cloned().unwrap_or_default(),
            ))
        })
    };
    let payload_change = |payload| Msg::Rules(RulesMsg::DraftPayload(payload));
    let (payload_label, payload) = match draft.kind.as_str() {
        "MATCH" => (
            text.field_payload(),
            text_field("", "", false, payload_change),
        ),
        "GEOIP" => (
            text.field_country(),
            choice(COUNTRIES.iter().map(|code| (*code).into()).collect(), true),
        ),
        "NETWORK" => (
            text.field_network(),
            choice(
                NETWORKS.iter().map(|network| (*network).into()).collect(),
                true,
            ),
        ),
        "RULE-SET" => (
            text.field_rule_set(),
            choice(providers.clone(), !providers.is_empty())
                .tooltip(providers.is_empty().then(|| text.no_rule_sets().into())),
        ),
        "PROCESS-NAME" | "PROCESS-PATH" => (
            text.field_payload(),
            row(
                8.0,
                vec![
                    text_field(
                        draft.payload.clone(),
                        text.payload_placeholder(&draft.kind),
                        open,
                        payload_change,
                    )
                    .grow(),
                    button(text.pick_executable(), ButtonStyle::Secondary)
                        .enabled(open)
                        .on_press(Msg::Rules(RulesMsg::PickExecutable)),
                ],
            ),
        ),
        _ => (
            text.field_payload(),
            text_field(
                draft.payload.clone(),
                text.payload_placeholder(&draft.kind),
                open,
                payload_change,
            ),
        ),
    };
    let inventory = state
        .nodes
        .inventory()
        .ready()
        .map(|inventory| &inventory.inventory)
        .filter(|inventory| inventory.profile_id == draft.profile_id);
    let mut outbound_options = outbounds(inventory);
    if !outbound_options.contains(&draft.outbound) {
        outbound_options.insert(0, draft.outbound.clone());
    }
    let outbound_index = outbound_options
        .iter()
        .position(|outbound| *outbound == draft.outbound);
    let outbound_names = outbound_options.clone();
    let outbound = select(outbound_options, outbound_index, open, move |index| {
        Msg::Rules(RulesMsg::DraftOutbound(
            outbound_names.get(index).cloned().unwrap_or_default(),
        ))
    });
    let resolves = takes_no_resolve(&draft.kind);
    let no_resolve = row(
        8.0,
        vec![
            crate::node::text("no-resolve", TextStyle::Body, Tone::Default),
            spacer(),
            switch(draft.no_resolve && resolves, resolves && open, |on| {
                Msg::Rules(RulesMsg::DraftNoResolve(on))
            }),
        ],
    );
    let title = if draft.rule_id.is_some() {
        text.edit_rule()
    } else {
        text.add_rule()
    };
    column(
        14.0,
        vec![
            heading(title),
            labelled(text.field_kind(), kind),
            labelled(payload_label, payload),
            labelled(text.field_outbound(), outbound),
            no_resolve,
            row(
                8.0,
                vec![
                    // A failed save says why where the user saved.
                    match &draft.error {
                        Some(error) => paragraph(error.clone(), Tone::Danger).grow(),
                        None => spacer(),
                    },
                    button(text.cancel(), ButtonStyle::Plain)
                        .key(ButtonKey::Escape)
                        .enabled(open)
                        .on_press(Msg::CloseDialog),
                    button(text.save(), ButtonStyle::Primary)
                        .key(ButtonKey::Return)
                        .busy(draft.pending)
                        .enabled(draft.can_save(&providers))
                        .on_press(Msg::Rules(RulesMsg::Save)),
                ],
            ),
        ],
    )
    .width(440.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::Kind;

    fn rule<'a>(kind: RuleKind, payload: Option<&'a str>, outbound: &'a str) -> RouteRule<'a> {
        RouteRule {
            kind,
            payload,
            outbound,
            no_resolve: false,
        }
    }

    fn list(rules: Vec<RouteRule<'_>>) -> ProfileRuleList {
        ProfileRuleList {
            profile_id: "p".into(),
            source_revision: "s1".into(),
            rules: rules.into(),
            unknown_kinds: HashMap::new(),
            unsupported: HashMap::new(),
            rule_providers: vec![
                SavedRuleProvider {
                    name: "ads".into(),
                    url: Some("https://example.com/ads.yaml".into()),
                    behavior: Some("domain".into()),
                    fetched_at_unix: Some(1),
                    entry_count: Some(120),
                },
                SavedRuleProvider {
                    name: "cn".into(),
                    url: Some("https://example.com/cn.yaml".into()),
                    behavior: Some("ipcidr".into()),
                    fetched_at_unix: None,
                    entry_count: None,
                },
            ],
        }
    }

    fn state_with(rules: Vec<RouteRule<'_>>) -> State {
        state_listing(list(rules))
    }

    fn state_listing(list: ProfileRuleList) -> State {
        let mut state = State::new(Lang::En);
        state.active_profile = Remote::Ready(Some(egrio_desktop::models::SavedProfileSummary {
            id: "p".into(),
            name: "Profile".into(),
            revision: "1".into(),
            source_revision: "s1".into(),
            traffic_policy_mode: TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: 0,
            groups: 0,
            rules: 0,
            updated_at_unix: 0,
        }));
        state.rules.set_list(Remote::Ready(list));
        state
    }

    fn shown(state: &State) -> Table {
        let tree = view(state);
        match &tree.children[1].kind {
            Kind::Table(table) => table.clone(),
            other => panic!("the rules table, not {other:?}"),
        }
    }

    fn sample() -> Vec<RouteRule<'static>> {
        vec![
            rule(RuleKind::DomainSuffix, Some("google.com"), "Proxy"),
            rule(RuleKind::RuleSet, Some("ads"), "REJECT"),
            rule(RuleKind::RuleSet, Some("cn"), "DIRECT"),
            rule(RuleKind::Match, None, "Proxy"),
        ]
    }

    #[test]
    fn a_rule_shows_its_type_content_outbound_and_hits() {
        let mut state = state_with(sample());
        state.rules.set_hits(HashMap::from([(
            "DOMAIN-SUFFIX,google.com,Proxy".to_string(),
            7,
        )]));
        let table = shown(&state);
        let first = &table.rows[0].cells;
        assert_eq!(
            first[0],
            Cell::Text {
                text: "DOMAIN-SUFFIX".into(),
                tone: Tone::Muted,
                mono: true
            }
        );
        assert_eq!(
            first[2],
            Cell::Badge {
                text: "Proxy".into(),
                tone: Tone::Accent
            }
        );
        assert_eq!(first[3], Cell::Number("7".into()));
        let Cell::Inline(ads) = &table.rows[1].cells[1] else {
            panic!("a rule set shows its link and its entries");
        };
        assert_eq!(
            ads[0],
            Cell::Text {
                text: "https://example.com/ads.yaml".into(),
                tone: Tone::Default,
                mono: true
            }
        );
        assert_eq!(
            ads[1],
            Cell::Badge {
                text: "120 entries".into(),
                tone: Tone::Success
            }
        );
        let Cell::Inline(cn) = &table.rows[2].cells[1] else {
            unreachable!()
        };
        assert_eq!(
            cn[1],
            Cell::Badge {
                text: "Not downloaded".into(),
                tone: Tone::Warning
            }
        );
        assert_eq!(
            table.rows[1].cells[2],
            Cell::Badge {
                text: "REJECT".into(),
                tone: Tone::Danger
            }
        );
        assert_eq!(
            table.rows[3].cells[1],
            Cell::Inline(vec![Cell::Text {
                text: "*".into(),
                tone: Tone::Default,
                mono: true
            }])
        );
    }

    /// A rule the Core leaves out is listed with the type it was written
    /// with and marked, and its dialog starts from that type.
    #[test]
    fn a_rule_the_core_leaves_out_is_marked_and_keeps_its_type() {
        let mut listed = list(vec![
            rule(RuleKind::Unknown, Some("13335"), "Proxy"),
            rule(RuleKind::Match, None, "DIRECT"),
        ]);
        listed.unknown_kinds.insert(0, "ip-asn".into());
        listed
            .unsupported
            .insert(0, "rule kind is not implemented".into());
        let state = state_listing(listed);
        let table = shown(&state);
        assert_eq!(
            table.rows[0].cells[0],
            Cell::Text {
                text: "IP-ASN".into(),
                tone: Tone::Muted,
                mono: true
            }
        );
        assert_eq!(
            table.rows[0].cells[1],
            Cell::Inline(vec![
                Cell::Text {
                    text: "13335".into(),
                    tone: Tone::Default,
                    mono: true
                },
                Cell::Badge {
                    text: "Unsupported".into(),
                    tone: Tone::Warning
                },
            ])
        );
        let Cell::Inline(kept) = &table.rows[1].cells[1] else {
            unreachable!()
        };
        assert_eq!(kept.len(), 1, "a rule the Core applies has no mark");

        let Remote::Ready(list) = &state.rules.list else {
            unreachable!()
        };
        let draft = RuleDraft::edit(list, 0).expect("the rule is listed");
        assert_eq!(draft.kind, "IP-ASN");
        assert_eq!(draft.rule_id.as_deref(), Some("rule-0"));
    }

    #[test]
    fn the_filter_narrows_the_rules_and_stops_reordering() {
        let mut state = state_with(sample());
        assert!(shown(&state).on_move.is_some());
        state.rules.filter = "reject ADS".into();
        let table = shown(&state);
        let keys: Vec<_> = table.rows.iter().map(|row| row.key.as_str()).collect();
        assert_eq!(keys, ["rule-1"]);
        assert!(table.on_move.is_none(), "only the whole list moves");
        state.rules.filter = "example.com/cn".into();
        assert_eq!(
            shown(&state).rows[0].key,
            "rule-2",
            "a rule set's link matches"
        );
    }

    /// Deleting removes what the page counts as selected: a rule selected
    /// before the filter hid it stays.
    #[test]
    fn a_selected_rule_the_filter_hides_is_not_among_those_to_delete() {
        let mut state = state_with(sample());
        state.rules.selected = vec!["rule-0".into(), "rule-1".into(), "rule-3".into()];
        assert_eq!(shown_selection(&state), ["rule-0", "rule-1", "rule-3"]);
        state.rules.filter = "ads".into();
        assert_eq!(shown_selection(&state), ["rule-1"]);
        assert_eq!(shown(&state).selected, ["rule-1"]);
        state.rules.filter = "nothing has this".into();
        assert!(shown_selection(&state).is_empty());
    }

    #[test]
    fn a_selection_made_in_another_version_of_the_file_is_dropped() {
        let mut state = state_with(sample());
        state.rules.selected = vec!["rule-1".into()];
        state.rules.set_list(Remote::Ready(list(sample())));
        assert_eq!(
            state.rules.selected,
            ["rule-1"],
            "the same version keeps it"
        );
        let mut changed = list(sample());
        changed.source_revision = "s2".into();
        state.rules.set_list(Remote::Ready(changed));
        assert!(state.rules.selected.is_empty());
    }

    #[test]
    fn rows_are_reused_until_what_they_show_changes() {
        let mut state = state_with(sample());
        let rows = |state: &State| shown(state).rows.clone();
        let first = rows(&state);
        assert!(Rc::ptr_eq(&first, &rows(&state)));
        state.rules.set_hits(HashMap::new());
        assert!(Rc::ptr_eq(&first, &rows(&state)), "the same counts");
        state
            .rules
            .set_hits(HashMap::from([("MATCH,Proxy".to_string(), 1)]));
        assert!(!Rc::ptr_eq(&first, &rows(&state)));
    }

    #[test]
    fn a_rule_keeps_its_hits_when_another_is_added_ahead_of_it() {
        let mut state = state_with(sample());
        let hits = HashMap::from([
            ("DOMAIN-SUFFIX,google.com,Proxy".to_string(), 7),
            ("MATCH,Proxy".to_string(), 2),
        ]);
        state.rules.set_hits(hits);
        let counts = |state: &State| -> Vec<Cell> {
            shown(state)
                .rows
                .iter()
                .map(|row| row.cells[3].clone())
                .collect()
        };
        let number = |count: u64| Cell::Number(count.to_string());
        assert_eq!(counts(&state), [number(7), number(0), number(0), number(2)]);

        // A new rule goes first, and every rule after it takes the next
        // place in the file: an id is a place, not a rule.
        state.rules.set_list(Remote::Ready(list(vec![
            rule(RuleKind::Domain, Some("new.example"), "DIRECT"),
            rule(RuleKind::DomainSuffix, Some("google.com"), "Proxy"),
            rule(RuleKind::RuleSet, Some("ads"), "REJECT"),
            rule(RuleKind::RuleSet, Some("cn"), "DIRECT"),
            rule(RuleKind::Match, None, "Proxy"),
        ])));
        assert_eq!(
            counts(&state),
            [number(0), number(7), number(0), number(0), number(2)]
        );
    }

    #[test]
    fn a_reorder_shows_the_new_order_at_once() {
        let mut state = state_with(sample());
        let moved = ["rule-3", "rule-0", "rule-1", "rule-2"].map(String::from);
        state.rules.reorder(&moved);
        let keys = |state: &State| -> Vec<String> {
            shown(state)
                .rows
                .iter()
                .map(|row| row.key.clone())
                .collect()
        };
        // Each row keeps the id of the file the page still holds.
        assert_eq!(keys(&state), moved);
        assert_eq!(
            shown(&state).rows[0].cells[0],
            Cell::Text {
                text: "MATCH".into(),
                tone: Tone::Muted,
                mono: true
            }
        );
        // The file as saved is read again, and shows in its own order.
        state.rules.set_list(Remote::Ready(list(sample())));
        assert_eq!(keys(&state), ["rule-0", "rule-1", "rule-2", "rule-3"]);
    }

    #[test]
    fn a_new_type_clears_what_was_written_for_the_old_one() {
        let rules = list(sample());
        let providers = provider_names(&rules);
        let mut draft = RuleDraft::new(&rules);
        draft.payload = "google.com".into();
        draft.no_resolve = true;
        assert!(draft.can_save(&providers));
        draft.set_kind("GEOIP", &providers);
        assert_eq!((draft.payload.as_str(), draft.no_resolve), ("CN", false));
        draft.set_kind("RULE-SET", &providers);
        assert_eq!(draft.payload, "ads");
        assert!(draft.can_save(&providers));
        draft.set_kind("MATCH", &providers);
        assert!(draft.payload.is_empty() && draft.can_save(&providers));
        assert_eq!(draft.saved_payload(), None);
        draft.set_kind("DOMAIN", &providers);
        assert!(
            !draft.can_save(&providers),
            "a domain rule needs its domain"
        );
        draft.payload = "ads".into();
        draft.set_kind("RULE-SET", &[]);
        assert!(!draft.can_save(&[]), "no rule set to name");
    }

    #[test]
    fn a_failed_save_says_why_beside_the_buttons_without_another_row() {
        let state = state_with(sample());
        let list = list(sample());
        let mut draft = RuleDraft::new(&list);
        let rows = |draft: &RuleDraft| dialog(&state, draft).children.len();
        let before = rows(&draft);
        draft.error = Some("Couldn't add the rule: the file changed".into());
        let tree = dialog(&state, &draft);
        assert_eq!(tree.children.len(), before);
        let buttons = tree.children.last().unwrap();
        let Kind::Text(error) = &buttons.children[0].kind else {
            panic!("the error leads the button row");
        };
        assert_eq!(error.text, "Couldn't add the rule: the file changed");
        assert_eq!(error.tone, Tone::Danger);
        assert!(!error.single_line, "the whole reason shows");
    }

    #[test]
    fn an_edit_starts_from_the_rule_in_capitals() {
        let rules = list(sample());
        let draft = RuleDraft::edit(&rules, 1).expect("the rule is listed");
        assert_eq!(draft.kind, "RULE-SET");
        assert_eq!(draft.payload, "ads");
        assert_eq!(draft.rule_id.as_deref(), Some("rule-1"));
        assert!(RuleDraft::edit(&rules, 4).is_none());
    }

    #[test]
    fn outbounds_offer_the_built_ins_then_groups_then_nodes_once() {
        let inventory = crate::latency::tests::inventory(
            vec![crate::latency::tests::node("HK")],
            vec![crate::latency::tests::group("Proxy", "select", &["HK"])],
        );
        assert_eq!(
            outbounds(Some(&inventory)),
            ["DIRECT", "REJECT", "Proxy", "HK"]
        );
        assert_eq!(outbounds(None), ["DIRECT", "REJECT"]);
    }
}
