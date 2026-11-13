//! The connections page's reads and actions: the history's rows and the
//! programs' names and icons; the rules the rows name come with the rules
//! page's list.

use base64::Engine;
use egrio_desktop::operations::telemetry;
use egrio_platform::{ProcessDisplayIdentity, ProcessDisplayQuery};

use super::Ui;
use crate::backend::Backend;
use crate::msg::{ConnectionsMsg, Msg};
use crate::node::Image;
use crate::pages::connections;
use crate::state::ProcessDisplay;

/// At most this many programs per resolution request.
const PROCESS_BATCH: usize = 64;

impl<B: Backend> Ui<B> {
    pub(super) fn connections(&mut self, msg: ConnectionsMsg) {
        match msg {
            ConnectionsMsg::GroupBy(group_by) => {
                if self.state.group_by != group_by {
                    self.state.group_by = group_by;
                    self.state.selected_group = None;
                }
            }
            ConnectionsMsg::SelectGroup(key) => self.state.selected_group = Some(key),
            ConnectionsMsg::Search(search) => self.state.connection_search = search,
            ConnectionsMsg::Select(id) => self.state.selected_connection = id,
            ConnectionsMsg::Sort(column) => {
                self.state.sort = connections::sort_key(self.state.group_by, column);
            }
            ConnectionsMsg::Clear => {
                telemetry::clear_finished_connections(&self.desktop.history);
                self.load_connections();
            }
        }
    }

    /// The rows that changed since the table's revision, an in-memory read.
    pub(super) fn load_connections(&mut self) {
        let update =
            telemetry::traffic_connections(&self.desktop.history, self.state.connections.revision);
        self.state.connections.apply(update);
        self.resolve_processes();
    }

    fn resolve_processes(&mut self) {
        let unresolved = connections::unresolved_processes(&self.state);
        for batch in unresolved.chunks(PROCESS_BATCH) {
            let queries: Vec<ProcessDisplayQuery> = batch
                .iter()
                .map(|(key, identifier, path)| {
                    self.state.resolving.insert(key.clone());
                    ProcessDisplayQuery {
                        identifier: identifier.clone(),
                        path: path.clone(),
                    }
                })
                .collect();
            self.spawn(async move {
                let identities = telemetry::resolve_process_display_identities(queries.clone())
                    .await
                    .unwrap_or_default();
                // Every platform keeps the queries' order; anything else reads
                // as unresolved.
                let ordered = identities.len() == queries.len()
                    && identities
                        .iter()
                        .zip(&queries)
                        .all(|(identity, query)| identity.identifier == query.identifier);
                Msg::ProcessIdentities {
                    queries,
                    identities: if ordered { identities } else { Vec::new() },
                }
            });
        }
    }

    /// The names and icons the programs resolved to; a program without an
    /// answer shows as unresolved.
    pub(super) fn process_identities(
        &mut self,
        queries: Vec<ProcessDisplayQuery>,
        identities: Vec<ProcessDisplayIdentity>,
    ) {
        for (query, identity) in queries.iter().zip(&identities) {
            let key = connections::process_key(&query.identifier, query.path.as_deref());
            let icon = identity
                .icon_png_base64
                .as_deref()
                .and_then(|encoded| {
                    base64::engine::general_purpose::STANDARD
                        .decode(encoded)
                        .ok()
                })
                .map(|bytes| Image(bytes.into()));
            self.state.resolving.remove(&key);
            self.state.process_displays.insert(
                key,
                ProcessDisplay {
                    name: identity.display_name.clone(),
                    icon,
                },
            );
        }
        for query in queries.iter().skip(identities.len()) {
            let key = connections::process_key(&query.identifier, query.path.as_deref());
            self.state.resolving.remove(&key);
            self.state.process_displays.insert(
                key,
                ProcessDisplay {
                    name: None,
                    icon: None,
                },
            );
        }
        connections::forget_unnamed_displays(&mut self.state);
        self.state.displays_revision += 1;
    }
}
