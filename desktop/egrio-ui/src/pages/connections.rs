//! The connections page: the history's rows, flat or grouped by host or by
//! program and narrowed by a search, the details of the selected connection,
//! and the totals.
//!
//! The table keeps only the columns worth scanning (protocol, the program in
//! the flat view, target, outbound, state, download); everything else lives
//! in the details under the table.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use egrio_core::{
    ConnectionFailureCause, ConnectionTermination, EgressPolicyRejection, OutboundStage,
    TcpFlowBudget, TcpFlowIoAction, TcpFlowIoSide, TcpFlowStage, TrafficConnectionProtocol,
    TrafficConnectionSnapshot, TrafficConnectionState,
};
use egrio_desktop::connection_history::{ConnectionRow, ConnectionsUpdate, TrafficTotals};

use crate::format;
use crate::msg::{ConnectionsMsg, Msg};
use crate::node::{
    self, badge, button, card, column, fact, facts, field, fields, icon_button, row, search_field,
    segmented, spacer, split, table, Cell, Column, ColumnAlign, ColumnWidth, Handler, Icon, Node,
    Row, Selection, SortDirection, Table, TextStyle, Tone,
};
use crate::state::{GroupBy, ProcessDisplay, State};
use crate::text::Text;

/// The table as of a history revision: its rows newest first. They are the
/// history's own rows, held with it.
#[derive(Debug, Clone, Default)]
pub struct ConnectionsView {
    pub revision: Option<u64>,
    pub connections: Vec<ConnectionRow>,
    pub totals: Option<TrafficTotals>,
    memo: Memo,
}

/// The table rows built for the last render, reused while nothing they show
/// changed.
#[derive(Debug, Clone, Default)]
struct Memo(RefCell<Option<MemoEntry>>);

/// The last projection and its rows. A new revision reuses each unchanged
/// connection's row; rows no longer shown leave the cache at the same time.
#[derive(Debug, Clone)]
struct MemoEntry {
    key: MemoKey,
    table: Rc<Vec<Rc<Row>>>,
    groups: Rc<Vec<Rc<Row>>>,
    rendered: HashMap<Arc<str>, (ConnectionRow, Rc<Row>)>,
}

#[derive(Debug, Clone, PartialEq)]
struct MemoKey {
    revision: Option<u64>,
    group_by: GroupBy,
    group: Option<String>,
    search: String,
    sort: Option<(SortKey, SortDirection)>,
    displays: u64,
    lang: crate::text::Lang,
}

/// The history's order: newest connection first, then by id.
fn newer_first(a: &ConnectionRow, b: &ConnectionRow) -> std::cmp::Ordering {
    b.opened_at_unix
        .cmp(&a.opened_at_unix)
        .then_with(|| a.id.cmp(&b.id))
}

impl ConnectionsView {
    /// Gives the rows back to the history, and with them the table rows
    /// built from them: a table that is not shown asks for no updates, so
    /// the rows it went on holding would be the ones the history has since
    /// replaced. The table reads every row again when it shows, a pointer
    /// each.
    pub fn release(&mut self) {
        *self = Self::default();
    }

    /// Applies one update from the history: rows the update leaves alone stay
    /// where they are, changed rows keep their place, new rows merge in the
    /// history's order.
    pub fn apply(&mut self, update: ConnectionsUpdate) {
        if update.full || self.revision.is_none() {
            self.connections = update.rows;
        } else if !update.rows.is_empty() || !update.removed.is_empty() {
            let removed: std::collections::HashSet<_> = update.removed.into_iter().collect();
            let mut changed: HashMap<std::sync::Arc<str>, ConnectionRow> = update
                .rows
                .into_iter()
                .map(|row| (row.id.clone(), row))
                .collect();
            let mut kept = Vec::with_capacity(self.connections.len());
            for row in self.connections.drain(..) {
                match changed.remove(&row.id) {
                    // The same connection keeps its place; an id that now names
                    // another connection (a restarted Core reuses ids) goes where
                    // that one sorts.
                    Some(next) if next.opened_at_unix == row.opened_at_unix => kept.push(next),
                    Some(next) => {
                        changed.insert(next.id.clone(), next);
                    }
                    None if !removed.contains(&row.id) => kept.push(row),
                    None => {}
                }
            }
            let mut added: Vec<_> = changed.into_values().collect();
            added.sort_by(newer_first);
            self.connections = merge_sorted(kept, added);
        }
        self.revision = Some(update.revision);
        self.totals = Some(update.totals);
    }
}

fn merge_sorted(a: Vec<ConnectionRow>, b: Vec<ConnectionRow>) -> Vec<ConnectionRow> {
    if b.is_empty() {
        return a;
    }
    let mut merged = Vec::with_capacity(a.len() + b.len());
    let mut a = a.into_iter().peekable();
    let mut b = b.into_iter().peekable();
    loop {
        match (a.peek(), b.peek()) {
            (Some(left), Some(right)) => {
                if newer_first(left, right).is_le() {
                    merged.push(a.next().unwrap());
                } else {
                    merged.push(b.next().unwrap());
                }
            }
            (Some(_), None) => merged.push(a.next().unwrap()),
            (None, Some(_)) => merged.push(b.next().unwrap()),
            (None, None) => return merged,
        }
    }
}

/// The key that tells programs apart: the attributed name and the executable
/// path, so two executables with the same filename never share an icon.
pub fn process_key(identifier: &str, path: Option<&str>) -> String {
    format!("{identifier}\u{0}{}", path.unwrap_or(""))
}

fn connection_process_key(connection: &TrafficConnectionSnapshot) -> Option<String> {
    let name = connection.process_name.as_deref()?.trim();
    (!name.is_empty()).then(|| process_key(name, connection.process_path.as_deref()))
}

/// How many resolved programs are kept before the ones no row names go.
const DISPLAYS_KEPT: usize = 512;

/// Lets go of the names and icons of programs no row names any more, once
/// more are kept than a table of programs needs. A display is kept past its
/// rows so that a program that comes back shows its icon at once; kept
/// without end, the map held every executable that ever had a connection
/// while the table showed, a few KiB each, for as long as the app ran.
pub fn forget_unnamed_displays(state: &mut State) {
    if state.process_displays.len() <= DISPLAYS_KEPT {
        return;
    }
    let named: std::collections::HashSet<String> = state
        .connections
        .connections
        .iter()
        .filter_map(|connection| connection_process_key(connection))
        .collect();
    state.process_displays.retain(|key, _| named.contains(key));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Protocol,
    Process,
    Target,
    Outbound,
    State,
    Download,
}

fn columns_for(group_by: GroupBy) -> Vec<SortKey> {
    let mut keys = vec![SortKey::Protocol];
    if group_by == GroupBy::None {
        keys.push(SortKey::Process);
    }
    keys.extend([
        SortKey::Target,
        SortKey::Outbound,
        SortKey::State,
        SortKey::Download,
    ]);
    keys
}

/// The sort the table shows, as a column of the current layout.
pub fn sort_column(state: &State) -> Option<(usize, SortDirection)> {
    let (key, direction) = state.sort?;
    columns_for(state.group_by)
        .iter()
        .position(|candidate| *candidate == key)
        .map(|index| (index, direction))
}

/// The table's sort event, as the key it names in the current layout.
pub fn sort_key(
    group_by: GroupBy,
    column: Option<(usize, SortDirection)>,
) -> Option<(SortKey, SortDirection)> {
    let (index, direction) = column?;
    columns_for(group_by)
        .get(index)
        .map(|key| (*key, direction))
}

fn state_order(state: TrafficConnectionState) -> u8 {
    match state {
        TrafficConnectionState::Active => 0,
        TrafficConnectionState::Completed => 1,
        TrafficConnectionState::Cancelled => 2,
        TrafficConnectionState::Rejected => 3,
        TrafficConnectionState::Failed => 4,
        TrafficConnectionState::Unknown => 5,
    }
}

fn sorted<'a>(
    connections: impl Iterator<Item = &'a ConnectionRow>,
    sort: Option<(SortKey, SortDirection)>,
    text: Text,
) -> Vec<&'a ConnectionRow> {
    let mut rows: Vec<_> = connections.collect();
    let Some((key, direction)) = sort else {
        return rows;
    };
    let unknown = text.unknown_process();
    rows.sort_by(|a, b| {
        let ordering = match key {
            SortKey::Protocol => protocol_label(&a.protocol).cmp(protocol_label(&b.protocol)),
            SortKey::Process => a
                .process_name
                .as_deref()
                .unwrap_or(unknown)
                .cmp(b.process_name.as_deref().unwrap_or(unknown)),
            SortKey::Target => target(a).cmp(target(b)),
            SortKey::Outbound => a.outbound.cmp(&b.outbound),
            SortKey::State => state_order(a.state).cmp(&state_order(b.state)),
            SortKey::Download => a.download_bytes.cmp(&b.download_bytes),
        };
        match direction {
            SortDirection::Ascending => ordering,
            SortDirection::Descending => ordering.reverse(),
        }
    });
    rows
}

fn target(connection: &TrafficConnectionSnapshot) -> &str {
    connection
        .host
        .as_deref()
        .unwrap_or(&connection.destination)
}

fn protocol_label(protocol: &TrafficConnectionProtocol) -> &'static str {
    match protocol {
        TrafficConnectionProtocol::Tcp => "TCP",
        TrafficConnectionProtocol::Udp => "UDP",
    }
}

#[derive(Debug, Clone)]
struct Group<'a> {
    key: String,
    label: String,
    process: Option<String>,
    connections: Vec<&'a ConnectionRow>,
    bytes: u64,
}

/// Connections bucketed by host or program, busiest first.
fn groups<'a>(connections: &[&'a ConnectionRow], group_by: GroupBy, text: Text) -> Vec<Group<'a>> {
    let mut groups: Vec<Group<'a>> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for &connection in connections {
        let identifier = connection
            .process_name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty());
        let (key, label) = match group_by {
            GroupBy::Host => {
                let host = connection
                    .host
                    .as_deref()
                    .map(str::trim)
                    .filter(|host| !host.is_empty());
                let label = host.unwrap_or(&connection.destination).to_string();
                (label.clone(), label)
            }
            _ => (
                connection_process_key(connection).unwrap_or_default(),
                identifier.unwrap_or(text.unknown_process()).to_string(),
            ),
        };
        let position = *index.entry(key.clone()).or_insert_with(|| {
            groups.push(Group {
                key: key.clone(),
                label,
                process: (group_by == GroupBy::Process)
                    .then(|| key.clone())
                    .filter(|key| !key.is_empty()),
                connections: Vec::new(),
                bytes: 0,
            });
            groups.len() - 1
        });
        let group = &mut groups[position];
        group.connections.push(connection);
        group.bytes += connection.upload_bytes + connection.download_bytes;
    }
    groups.sort_by_key(|group| std::cmp::Reverse(group.bytes));
    groups
}

fn state_cell(state: TrafficConnectionState, text: Text) -> Cell {
    let (label, tone) = match state {
        TrafficConnectionState::Active => (text.state_active(), Tone::Success),
        TrafficConnectionState::Completed => (text.state_completed(), Tone::Muted),
        TrafficConnectionState::Cancelled => (text.state_cancelled(), Tone::Muted),
        TrafficConnectionState::Rejected => (text.state_rejected(), Tone::Warning),
        TrafficConnectionState::Failed => (text.state_failed(), Tone::Danger),
        TrafficConnectionState::Unknown => (text.state_unknown(), Tone::Muted),
    };
    Cell::Status {
        text: label.into(),
        tone,
    }
}

fn display_name<'a>(
    connection: &'a TrafficConnectionSnapshot,
    displays: &'a HashMap<String, ProcessDisplay>,
) -> Option<(&'a str, Option<&'a ProcessDisplay>)> {
    let name = connection.process_name.as_deref()?.trim();
    if name.is_empty() {
        return None;
    }
    let display = connection_process_key(connection).and_then(|key| displays.get(&key));
    Some((
        display
            .and_then(|display| display.name.as_deref())
            .unwrap_or(name),
        display,
    ))
}

fn connection_row(
    connection: &TrafficConnectionSnapshot,
    with_process: bool,
    displays: &HashMap<String, ProcessDisplay>,
    text: Text,
) -> Row {
    let mut cells = vec![Cell::Badge {
        text: protocol_label(&connection.protocol).into(),
        tone: Tone::Muted,
    }];
    if with_process {
        cells.push(match display_name(connection, displays) {
            Some((name, display)) => Cell::Process {
                name: name.into(),
                icon: display.and_then(|display| display.icon.clone()),
            },
            None => Cell::Process {
                name: text.unknown_process().into(),
                icon: None,
            },
        });
    }
    cells.push(Cell::Text {
        text: target(connection).into(),
        tone: Tone::Default,
        mono: false,
    });
    cells.push(Cell::Badge {
        text: connection.outbound.to_string(),
        tone: Tone::Accent,
    });
    cells.push(state_cell(connection.state, text));
    cells.push(Cell::Number(format::bytes(connection.download_bytes)));
    Row {
        key: connection.id.to_string(),
        cells,
    }
}

fn table_columns(group_by: GroupBy, text: Text) -> Vec<Column> {
    columns_for(group_by)
        .into_iter()
        .map(|key| {
            let (title, width) = match key {
                SortKey::Protocol => (text.col_protocol(), ColumnWidth::Fixed(56.0)),
                SortKey::Process => (text.col_process(), ColumnWidth::Fixed(150.0)),
                // Beside the group list the target gives way further.
                SortKey::Target => (
                    text.col_target(),
                    ColumnWidth::Flexible {
                        min: if group_by == GroupBy::None {
                            140.0
                        } else {
                            100.0
                        },
                    },
                ),
                SortKey::Outbound => (text.col_outbound(), ColumnWidth::Fixed(110.0)),
                SortKey::State => (text.col_state(), ColumnWidth::Fixed(80.0)),
                SortKey::Download => (text.col_download(), ColumnWidth::Fixed(80.0)),
            };
            Column {
                title: title.into(),
                width,
                align: if key == SortKey::Download {
                    ColumnAlign::Trailing
                } else {
                    ColumnAlign::Leading
                },
                sortable: true,
            }
        })
        .collect()
}

pub fn termination_text(termination: &ConnectionTermination, text: Text) -> String {
    match termination {
        ConnectionTermination::Completed => text.termination_completed().into(),
        ConnectionTermination::Cancelled => text.termination_cancelled().into(),
        ConnectionTermination::ClientClosed { .. } => text.termination_client_closed().into(),
        ConnectionTermination::RouteRejected => text.termination_route_rejected().into(),
        ConnectionTermination::PolicyRejected { reason } => match reason {
            EgressPolicyRejection::ScopedTargetRequiresDirect => {
                text.termination_scoped_requires_direct().into()
            }
            EgressPolicyRejection::UnresolvedIpv6Scope => {
                text.termination_scope_unresolved().into()
            }
        },
        ConnectionTermination::Failed { stage, cause } => {
            text.termination_failure(stage_label(*stage, text), &failure_text(cause, text))
        }
        ConnectionTermination::Unknown => text.termination_unknown().into(),
    }
}

fn stage_label(stage: TcpFlowStage, text: Text) -> &'static str {
    match stage {
        TcpFlowStage::Admission => text.stage_admission(),
        TcpFlowStage::Enrich => text.stage_enrich(),
        TcpFlowStage::Route => text.stage_route(),
        TcpFlowStage::Dial => text.stage_dial(),
        TcpFlowStage::Reply => text.stage_reply(),
        TcpFlowStage::Relay => text.stage_relay(),
    }
}

fn io_message(message: &str, error_kind: &str, os_code: Option<i32>, text: Text) -> String {
    if !message.is_empty() {
        return message.into();
    }
    match os_code {
        Some(code) => format!("{error_kind} ({})", text.failure_os_code(code)),
        None => error_kind.into(),
    }
}

fn failure_text(cause: &ConnectionFailureCause, text: Text) -> String {
    match cause {
        ConnectionFailureCause::Io {
            side,
            action,
            error_kind,
            os_code,
            message,
        } => {
            let side = match side {
                TcpFlowIoSide::Client => text.side_client(),
                TcpFlowIoSide::Upstream => text.side_upstream(),
            };
            text.failure_io(
                side,
                action_label(*action, text),
                &io_message(message, error_kind, *os_code, text),
            )
        }
        ConnectionFailureCause::UnattributedIo {
            error_kind,
            os_code,
            message,
        } => text.failure_unattributed_io(&io_message(message, error_kind, *os_code, text)),
        ConnectionFailureCause::Budget {
            budget,
            duration_ms,
        } => {
            let seconds = format::seconds(*duration_ms);
            match budget {
                TcpFlowBudget::Dial => text.failure_dial_timeout(&seconds),
                TcpFlowBudget::FirstUpstreamByte => text.failure_first_byte_timeout(&seconds),
                TcpFlowBudget::Idle => text.failure_idle_timeout(&seconds),
            }
        }
        ConnectionFailureCause::Outbound { stage, message } => {
            let stage = match stage {
                OutboundStage::Config => text.outbound_config(),
                OutboundStage::Local => text.outbound_local(),
                OutboundStage::HopResolve => text.outbound_hop_resolve(),
                OutboundStage::HopConnect => text.outbound_hop_connect(),
                OutboundStage::HopAuth => text.outbound_hop_auth(),
                OutboundStage::HopProtocol => text.outbound_hop_protocol(),
                OutboundStage::TargetResolve => text.outbound_target_resolve(),
                OutboundStage::Target => text.outbound_target(),
            };
            text.failure_outbound(stage, message)
        }
        ConnectionFailureCause::Message { message } => message.clone(),
    }
}

fn action_label(action: TcpFlowIoAction, text: Text) -> &'static str {
    match action {
        TcpFlowIoAction::Read => text.action_read(),
        TcpFlowIoAction::Write => text.action_write(),
        TcpFlowIoAction::Flush => text.action_flush(),
        TcpFlowIoAction::Shutdown => text.action_shutdown(),
    }
}

/// The search's words, lowercase.
/// Every word is in the connection's host, address, program, outbound or
/// protocol.
fn matches(
    connection: &TrafficConnectionSnapshot,
    terms: &[String],
    displays: &HashMap<String, ProcessDisplay>,
) -> bool {
    if terms.is_empty() {
        return true;
    }
    // One line per value, so a word never spans two of them.
    let haystack = [
        connection.host.as_deref(),
        Some(&*connection.destination),
        display_name(connection, displays).map(|(name, _)| name),
        connection.process_name.as_deref(),
        Some(&*connection.outbound),
        Some(protocol_label(&connection.protocol)),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>()
    .join("\n")
    .to_lowercase();
    terms.iter().all(|term| haystack.contains(term.as_str()))
}

/// Processes the shown rows name that have no display yet, to resolve.
pub fn unresolved_processes(state: &State) -> Vec<(String, String, Option<String>)> {
    let mut seen = std::collections::HashSet::new();
    state
        .connections
        .connections
        .iter()
        .filter_map(|connection| {
            let name = connection.process_name.as_deref()?.trim();
            let path = connection.process_path.as_deref();
            if name.is_empty() || !seen.insert((name, path)) {
                return None;
            }
            // Resolve programs, not their connections: a full table often
            // names only a handful of executables.
            let key = process_key(name, path);
            (!state.process_displays.contains_key(&key) && !state.resolving.contains(&key))
                .then(|| (key, name.to_string(), path.map(str::to_string)))
        })
        .collect()
}

fn rows(state: &State) -> (Rc<Vec<Rc<Row>>>, Rc<Vec<Rc<Row>>>) {
    let text = state.text();
    let key = MemoKey {
        revision: state.connections.revision,
        group_by: state.group_by,
        group: state.selected_group.clone(),
        search: state.connection_search.clone(),
        sort: state.sort,
        displays: state.displays_revision,
        lang: state.lang,
    };
    let mut memo = state.connections.memo.0.borrow_mut();
    if let Some(cached) = memo.as_ref() {
        if cached.key == key {
            return (cached.table.clone(), cached.groups.clone());
        }
    }
    // Filtering and sorting change the order, not a row's content. Language,
    // process displays and the presence of the program column change content.
    let mut previous = memo
        .take()
        .filter(|cached| {
            cached.key.lang == key.lang
                && cached.key.displays == key.displays
                && (cached.key.group_by == GroupBy::None) == (key.group_by == GroupBy::None)
        })
        .map(|cached| cached.rendered)
        .unwrap_or_default();
    let mut rendered = HashMap::new();
    let mut render = |connection: &ConnectionRow| {
        let row = previous
            .remove(&connection.id)
            .filter(|(source, _)| Arc::ptr_eq(source, connection))
            .map(|(_, row)| row)
            .unwrap_or_else(|| {
                Rc::new(connection_row(
                    connection,
                    state.group_by == GroupBy::None,
                    &state.process_displays,
                    text,
                ))
            });
        rendered.insert(connection.id.clone(), (connection.clone(), row.clone()));
        row
    };
    let terms = format::search_terms(&state.connection_search);
    let connections: Vec<&ConnectionRow> = state
        .connections
        .connections
        .iter()
        .filter(|connection| matches(connection, &terms, &state.process_displays))
        .collect();
    let (table_rows, group_rows) = if state.group_by == GroupBy::None {
        let rows: Vec<Rc<Row>> = sorted(connections.iter().copied(), state.sort, text)
            .into_iter()
            .map(&mut render)
            .collect();
        (rows, Vec::new())
    } else {
        let groups = groups(&connections, state.group_by, text);
        let selected = state
            .selected_group
            .as_ref()
            .and_then(|key| groups.iter().find(|group| &group.key == key))
            .or(groups.first());
        let table_rows = selected
            .map(|group| {
                sorted(group.connections.iter().copied(), state.sort, text)
                    .into_iter()
                    .map(&mut render)
                    .collect()
            })
            .unwrap_or_default();
        let group_rows = groups
            .iter()
            .map(|group| {
                let display = group
                    .process
                    .as_ref()
                    .and_then(|key| state.process_displays.get(key));
                Rc::new(Row {
                    key: group.key.clone(),
                    cells: vec![Cell::TwoLine {
                        title: display
                            .and_then(|display| display.name.clone())
                            .unwrap_or_else(|| group.label.clone()),
                        detail: text.connection_count(group.connections.len()),
                        icon: display.and_then(|display| display.icon.clone()),
                        fallback: if state.group_by == GroupBy::Host {
                            Icon::Globe
                        } else {
                            Icon::App
                        },
                        trailing: format::bytes(group.bytes),
                        trailing_tone: Tone::Muted,
                    }],
                })
            })
            .collect();
        (table_rows, group_rows)
    };
    let (table_rows, group_rows) = (Rc::new(table_rows), Rc::new(group_rows));
    *memo = Some(MemoEntry {
        key,
        table: table_rows.clone(),
        groups: group_rows.clone(),
        rendered,
    });
    (table_rows, group_rows)
}

/// The group whose connections the table shows: the chosen one while it
/// exists, otherwise the busiest.
pub fn shown_group(state: &State) -> Option<String> {
    if state.group_by == GroupBy::None {
        return None;
    }
    let (_, group_rows) = rows(state);
    state
        .selected_group
        .as_ref()
        .filter(|key| group_rows.iter().any(|row| &row.key == *key))
        .cloned()
        .or_else(|| group_rows.first().map(|row| row.key.clone()))
}

pub fn view(state: &State) -> Node {
    let text = state.text();
    let (table_rows, group_rows) = rows(state);
    let totals = state.connections.totals.clone().unwrap_or(TrafficTotals {
        upload_bytes: 0,
        download_bytes: 0,
        active_connections: 0,
        processes: 0,
    });
    let group_by_index = match state.group_by {
        GroupBy::None => 0,
        GroupBy::Host => 1,
        GroupBy::Process => 2,
    };
    let toolbar = row(
        12.0,
        vec![
            segmented(
                vec![
                    text.flat().into(),
                    text.by_host().into(),
                    text.by_process().into(),
                ],
                Some(group_by_index),
                true,
                |index| {
                    Msg::Connections(ConnectionsMsg::GroupBy(match index {
                        1 => GroupBy::Host,
                        2 => GroupBy::Process,
                        _ => GroupBy::None,
                    }))
                },
            ),
            spacer(),
            search_field(
                state.connection_search.clone(),
                text.search_connections(),
                |search| Msg::Connections(ConnectionsMsg::Search(search)),
            ),
            button(text.clear(), node::ButtonStyle::Plain)
                .icon(Icon::Clear)
                .on_press(Msg::Connections(ConnectionsMsg::Clear))
                .tooltip(Some(text.clear_tooltip().into())),
        ],
    );
    let empty = if state.connections.revision.is_none() {
        text.loading()
    } else if !state.connection_search.trim().is_empty() {
        text.connections_no_match()
    } else {
        text.connections_empty()
    };
    let selected = state
        .selected_connection
        .as_ref()
        .filter(|id| table_rows.iter().any(|row| &row.key == *id));
    let connection_table = table(Table {
        columns: table_columns(state.group_by, text),
        rows: table_rows,
        header: true,
        row_height: 32.0,
        selection: Selection::Single,
        selected: selected.cloned().into_iter().collect(),
        sort: sort_column(state),
        empty: Some(empty.into()),
        follow_end: false,
        wrap: false,
        on_select: Some(Handler::new(|keys: Vec<String>| {
            Msg::Connections(ConnectionsMsg::Select(keys.into_iter().next()))
        })),
        on_activate: None,
        on_sort: Some(Handler::new(|column| {
            Msg::Connections(ConnectionsMsg::Sort(column))
        })),
        on_move: None,
    })
    .grow()
    .key("connections");
    let body = if state.group_by == GroupBy::None {
        connection_table
    } else {
        let group_list = table(Table {
            columns: vec![Column {
                title: String::new(),
                width: ColumnWidth::Flexible { min: 160.0 },
                align: ColumnAlign::Leading,
                sortable: false,
            }],
            rows: group_rows,
            header: false,
            row_height: 44.0,
            selection: Selection::Single,
            selected: shown_group(state).into_iter().collect(),
            sort: None,
            empty: None,
            follow_end: false,
            wrap: false,
            on_select: Some(Handler::new(|keys: Vec<String>| {
                match keys.into_iter().next() {
                    Some(key) => Msg::Connections(ConnectionsMsg::SelectGroup(key)),
                    None => Msg::Connections(ConnectionsMsg::Select(None)),
                }
            })),
            on_activate: None,
            on_sort: None,
            on_move: None,
        })
        .key("groups");
        split(220.0, group_list, connection_table).grow()
    };
    let mut children = vec![toolbar, body];
    if let Some(connection) = selected.and_then(|id| {
        state
            .connections
            .connections
            .iter()
            .find(|connection| &*connection.id == id.as_str())
    }) {
        children.push(detail(connection, state));
    }
    // The totals close the page, where the search row leaves them room.
    children.push(facts(vec![
        fact(
            text.connections_active(),
            totals.active_connections.to_string(),
        ),
        fact(text.process_count(), totals.processes.to_string()),
        fact(text.upload_total(), format::bytes(totals.upload_bytes)),
        fact(text.download_total(), format::bytes(totals.download_bytes)),
    ]));
    card(children).grow()
}

fn detail(connection: &TrafficConnectionSnapshot, state: &State) -> Node {
    let text = state.text();
    let name = display_name(connection, &state.process_displays)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| text.unknown_process().into());
    let Cell::Status {
        text: state_label,
        tone,
    } = state_cell(connection.state, text)
    else {
        unreachable!()
    };
    let duration =
        connection.closed_at_unix.unwrap_or_else(format::now_unix) - connection.opened_at_unix;
    let mut items = vec![
        field(text.field_target(), target(connection)),
        field(text.field_address(), &*connection.destination),
        field(
            text.field_source(),
            connection.source.as_deref().unwrap_or("—"),
        ),
        field(text.field_rule(), connection.rule.as_deref().unwrap_or("—")),
        field(text.field_inbound(), connection.inbound),
        field(text.field_outbound(), &*connection.outbound),
        field(
            text.field_egress_interface(),
            connection
                .egress_interface
                .map(|index| format!("#{index}"))
                .unwrap_or_else(|| "—".into()),
        ),
        field(
            text.field_opened_at(),
            format::clock(connection.opened_at_unix),
        ),
        field(text.field_duration(), format::duration(duration)),
        field(text.upload(), format::bytes(connection.upload_bytes)),
        field(text.download(), format::bytes(connection.download_bytes)),
    ];
    if let Some(termination) = &connection.termination {
        let mut item = field(
            text.field_termination(),
            termination_text(termination, text),
        );
        item.wide = true;
        items.push(item);
    }
    column(
        10.0,
        vec![
            row(
                10.0,
                vec![
                    badge(protocol_label(&connection.protocol), Tone::Muted),
                    node::text(name, TextStyle::Heading, Tone::Default),
                    badge(state_label, tone),
                    spacer(),
                    icon_button(Icon::Close)
                        .on_press(Msg::Connections(ConnectionsMsg::Select(None)))
                        .tooltip(Some(text.close_detail().into())),
                ],
            ),
            fields(3, items),
        ],
    )
    .key("detail")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(id: &str, opened: i64) -> TrafficConnectionSnapshot {
        TrafficConnectionSnapshot {
            id: id.into(),
            protocol: TrafficConnectionProtocol::Tcp,
            process_name: None,
            process_path: None,
            source: None,
            destination: "1.1.1.1:443".into(),
            host: None,
            rule: None,
            inbound: "tun".into(),
            outbound: "DIRECT".into(),
            egress_interface: None,
            upload_bytes: 0,
            download_bytes: 0,
            opened_at_unix: opened,
            updated_at_unix: opened,
            state: TrafficConnectionState::Active,
            termination: None,
            closed_at_unix: None,
        }
    }

    fn update(
        revision: u64,
        rows: Vec<TrafficConnectionSnapshot>,
        removed: &[&str],
        full: bool,
    ) -> ConnectionsUpdate {
        ConnectionsUpdate {
            revision,
            full,
            totals: TrafficTotals {
                upload_bytes: 0,
                download_bytes: 0,
                active_connections: rows.len() as u64,
                processes: 0,
            },
            rows: rows.into_iter().map(std::sync::Arc::new).collect(),
            removed: removed.iter().map(|id| (*id).into()).collect(),
        }
    }

    fn ids(view: &ConnectionsView) -> Vec<&str> {
        view.connections
            .iter()
            .map(|connection| &*connection.id)
            .collect()
    }

    fn start() -> ConnectionsView {
        let mut view = ConnectionsView::default();
        view.apply(update(
            1,
            vec![
                connection("c", 30),
                connection("b", 20),
                connection("a", 10),
            ],
            &[],
            true,
        ));
        view
    }

    #[test]
    fn displays_of_programs_no_row_names_go_once_there_are_many() {
        let mut state = State::new(crate::text::Lang::En);
        let named = |name: &str| {
            let mut row = connection(name, 10);
            row.process_name = Some(name.into());
            row.process_path = Some(format!("/Applications/{name}").into());
            row
        };
        state
            .connections
            .apply(update(1, vec![named("a"), named("b")], &[], true));
        let display = || ProcessDisplay {
            name: None,
            icon: None,
        };
        for key in ["a", "b"] {
            let key = process_key(key, Some(&format!("/Applications/{key}")));
            state.process_displays.insert(key, display());
        }
        // A program that left the table keeps its display for when it comes
        // back, while there are few of them.
        for gone in 0..DISPLAYS_KEPT - 2 {
            state
                .process_displays
                .insert(process_key(&format!("gone-{gone}"), None), display());
        }
        forget_unnamed_displays(&mut state);
        assert_eq!(state.process_displays.len(), DISPLAYS_KEPT);

        state
            .process_displays
            .insert(process_key("one-more", None), display());
        forget_unnamed_displays(&mut state);
        let mut kept: Vec<_> = state.process_displays.keys().cloned().collect();
        kept.sort();
        assert_eq!(
            kept,
            [
                process_key("a", Some("/Applications/a")),
                process_key("b", Some("/Applications/b")),
            ]
        );
    }

    #[test]
    fn a_released_view_holds_no_row_and_asks_for_all_of_them() {
        let mut view = start();
        let row = view.connections[0].clone();
        assert_eq!(std::sync::Arc::strong_count(&row), 2);
        view.release();
        assert_eq!(std::sync::Arc::strong_count(&row), 1);
        assert!(view.connections.is_empty());
        assert_eq!(view.revision, None, "the next read is of every row");
    }

    #[test]
    fn a_full_update_replaces_the_view() {
        let mut view = start();
        view.apply(update(5, vec![connection("z", 1)], &[], true));
        assert_eq!(ids(&view), ["z"]);
        assert_eq!(view.revision, Some(5));
    }

    #[test]
    fn changed_rows_keep_their_place() {
        let mut view = start();
        let mut changed = connection("b", 20);
        changed.download_bytes = 9;
        view.apply(update(2, vec![changed], &[], false));
        assert_eq!(ids(&view), ["c", "b", "a"]);
        assert_eq!(view.connections[1].download_bytes, 9);
    }

    #[test]
    fn history_updates_rebuild_only_the_rows_that_changed() {
        let mut state = State::new(crate::text::Lang::En);
        state.connections = start();
        let (before, _) = rows(&state);
        let mut changed = connection("b", 20);
        changed.download_bytes = 4096;
        state
            .connections
            .apply(update(2, vec![connection("d", 40), changed], &["a"], false));
        let (after, _) = rows(&state);
        assert_eq!(
            after.iter().map(|row| row.key.as_str()).collect::<Vec<_>>(),
            ["d", "c", "b"]
        );
        assert!(Rc::ptr_eq(&before[0], &after[1]), "unchanged c is shared");
        assert!(!Rc::ptr_eq(&before[1], &after[2]), "b has new content");
        assert_eq!(
            after[2].cells.last(),
            Some(&Cell::Number(format::bytes(4096)))
        );
        assert!(!state
            .connections
            .memo
            .0
            .borrow()
            .as_ref()
            .unwrap()
            .rendered
            .contains_key("a"));
    }

    #[test]
    fn filtering_and_sorting_reuse_rows_but_changed_display_text_rebuilds_them() {
        let mut state = State::new(crate::text::Lang::En);
        let mut first = connection("a", 20);
        first.host = Some("example.org".into());
        first.process_name = Some("curl".into());
        let second = connection("b", 10);
        state
            .connections
            .apply(update(1, vec![first, second], &[], true));
        let (before, _) = rows(&state);
        state.connection_search = "example".into();
        state.sort = Some((SortKey::Target, SortDirection::Ascending));
        let (filtered, _) = rows(&state);
        assert_eq!(filtered.len(), 1);
        assert!(Rc::ptr_eq(&before[0], &filtered[0]));
        assert_eq!(
            state
                .connections
                .memo
                .0
                .borrow()
                .as_ref()
                .unwrap()
                .rendered
                .len(),
            1
        );

        state.process_displays.insert(
            process_key("curl", None),
            ProcessDisplay {
                name: Some("New name".into()),
                icon: None,
            },
        );
        state.displays_revision += 1;
        let (renamed, _) = rows(&state);
        assert!(matches!(&renamed[0].cells[1], Cell::Process { name, .. } if name == "New name"));
        state.lang = crate::text::Lang::Zh;
        let (translated, _) = rows(&state);
        assert!(!Rc::ptr_eq(&renamed[0], &translated[0]));
        assert_ne!(renamed[0].cells[4], translated[0].cells[4]);

        let row = Rc::downgrade(&translated[0]);
        drop((before, filtered, renamed, translated));
        state.connections.release();
        assert!(
            row.upgrade().is_none(),
            "closing the page releases rendered rows"
        );
    }

    #[test]
    fn new_rows_merge_in_order_and_removed_ones_go() {
        let mut view = start();
        view.apply(update(
            2,
            vec![
                connection("d", 40),
                connection("b2", 20),
                connection("aa", 15),
            ],
            &["c"],
            false,
        ));
        assert_eq!(ids(&view), ["d", "b", "b2", "aa", "a"]);
    }

    #[test]
    fn a_reused_id_moves_to_where_its_new_connection_sorts() {
        let mut view = start();
        view.apply(update(
            2,
            vec![connection("a", 50), connection("a@10", 10)],
            &[],
            false,
        ));
        assert_eq!(ids(&view), ["a", "c", "b", "a@10"]);
    }

    #[test]
    fn groups_come_busiest_first_and_programs_split_by_path() {
        let text = Text(crate::text::Lang::En);
        let mut first = connection("1", 1);
        first.process_name = Some("curl".into());
        first.process_path = Some("/usr/bin/curl".into());
        first.download_bytes = 10;
        let mut second = connection("2", 2);
        second.process_name = Some("curl".into());
        second.process_path = Some("/opt/curl".into());
        second.download_bytes = 100;
        let (first, second) = (Arc::new(first), Arc::new(second));
        let connections = vec![&first, &second];
        let grouped = groups(&connections, GroupBy::Process, text);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].bytes, 100);
        let by_host = groups(&connections, GroupBy::Host, text);
        assert_eq!(by_host.len(), 1);
        assert_eq!(by_host[0].label, "1.1.1.1:443");
    }

    fn searched(search: &str, group_by: GroupBy) -> (Vec<String>, Vec<String>) {
        let mut state = State::new(crate::text::Lang::En);
        let mut chrome = connection("chrome", 3);
        chrome.host = Some("www.Example.com".into());
        chrome.process_name = Some("com.google.Chrome".into());
        chrome.outbound = "Proxy".into();
        let mut curl = connection("curl", 2);
        curl.host = Some("api.example.org".into());
        curl.process_name = Some("curl".into());
        let mut dns = connection("dns", 1);
        dns.protocol = TrafficConnectionProtocol::Udp;
        dns.destination = "8.8.8.8:53".into();
        state
            .connections
            .apply(update(1, vec![chrome, curl, dns], &[], true));
        state.group_by = group_by;
        state.connection_search = search.into();
        let (table_rows, group_rows) = rows(&state);
        let keys = |rows: &[Rc<Row>]| rows.iter().map(|row| row.key.clone()).collect();
        (keys(&table_rows), keys(&group_rows))
    }

    #[test]
    fn the_search_finds_every_word_in_any_column_ignoring_case() {
        assert_eq!(searched("", GroupBy::None).0, ["chrome", "curl", "dns"]);
        assert_eq!(searched("EXAMPLE", GroupBy::None).0, ["chrome", "curl"]);
        assert_eq!(searched("example proxy", GroupBy::None).0, ["chrome"]);
        assert_eq!(searched("chrome", GroupBy::None).0, ["chrome"]);
        assert_eq!(searched("8.8.8", GroupBy::None).0, ["dns"]);
        assert_eq!(searched("udp", GroupBy::None).0, ["dns"]);
        assert!(searched("example dns", GroupBy::None).0.is_empty());
    }

    #[test]
    fn grouped_the_search_keeps_the_groups_with_a_match() {
        let (table_rows, group_rows) = searched("example", GroupBy::Host);
        assert_eq!(group_rows, ["www.Example.com", "api.example.org"]);
        assert_eq!(table_rows.len(), 1, "the busiest matching group shows");
        assert!(searched("nothing", GroupBy::Process).1.is_empty());
    }

    #[test]
    fn sort_columns_follow_the_layout() {
        assert_eq!(
            sort_key(GroupBy::None, Some((5, SortDirection::Descending))),
            Some((SortKey::Download, SortDirection::Descending))
        );
        assert_eq!(
            sort_key(GroupBy::Host, Some((4, SortDirection::Ascending))),
            Some((SortKey::Download, SortDirection::Ascending))
        );
        assert_eq!(
            sort_key(GroupBy::Host, Some((1, SortDirection::Ascending))),
            Some((SortKey::Target, SortDirection::Ascending))
        );
    }

    #[test]
    fn failures_read_as_their_stage_and_cause() {
        let text = Text(crate::text::Lang::En);
        let termination = ConnectionTermination::Failed {
            stage: TcpFlowStage::Dial,
            cause: ConnectionFailureCause::Budget {
                budget: TcpFlowBudget::Dial,
                duration_ms: 1500,
            },
        };
        assert_eq!(
            termination_text(&termination, text),
            "Connection setup: Connection timed out (1.5s)"
        );
    }
}
