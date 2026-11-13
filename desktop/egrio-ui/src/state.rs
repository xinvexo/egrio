//! The interface state: what the pages keep of their own (the section, the
//! table's grouping and selection) and the backend data they show. It lives
//! in the runtime, not in a window, so a closed and rebuilt main window comes
//! back as it was.

use std::collections::{HashMap, HashSet};

use egrio_core::{NativeCoreStatus, PortUnavailable, TrafficPolicyMode};
use egrio_desktop::connection_history::TrafficTotals;
use egrio_desktop::desktop_behavior::DesktopBehaviorSettings;
use egrio_desktop::geodata::GeoDataStatus;
use egrio_desktop::logging::LogLevel;
use egrio_desktop::models::{PublicIpInfo, SavedProfileSummary};
use egrio_desktop::operations::capture::CaptureStatus;
use egrio_desktop::profile_network_settings::{ProfileNetworkSetting, ProfileNetworkSettings};
use egrio_platform::{CaptureLayer, CaptureLayers};

use crate::chart::RateSeries;
use crate::editor::Editor;
use crate::latency::Latency;
use crate::messages::MessageLog;
use crate::node::{Image, SortDirection};
use crate::pages::connections::ConnectionsView;
use crate::pages::logs::{LogFilter, LogsView};
use crate::pages::nodes::NodesPage;
use crate::pages::profiles::AddProfile;
use crate::pages::rules::{RuleDraft, RulesPage};
use crate::text::{Lang, Text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Section {
    Activity,
    Nodes,
    Profiles,
    Rules,
    Connections,
    Logs,
    Settings,
}

impl Section {
    pub const ALL: [Section; 7] = [
        Section::Activity,
        Section::Nodes,
        Section::Profiles,
        Section::Rules,
        Section::Connections,
        Section::Logs,
        Section::Settings,
    ];
}

/// A value read from the backend: not yet, read, or the read failed.
#[derive(Debug, Clone, PartialEq)]
pub enum Remote<T> {
    Loading,
    Ready(T),
    Failed(String),
}

impl<T> Remote<T> {
    pub fn ready(&self) -> Option<&T> {
        match self {
            Remote::Ready(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBy {
    None,
    Host,
    Process,
}

/// An app's display name and icon for the connections table.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessDisplay {
    pub name: Option<String>,
    pub icon: Option<Image>,
}

#[derive(Debug)]
pub struct State {
    pub lang: Lang,
    pub section: Section,
    pub drawer_open: bool,
    pub messages: MessageLog,

    pub capture: Option<CaptureStatus>,
    /// The capture switch or profile configuration change that runs.
    pub change: Option<Running>,
    pub active_profile: Remote<Option<SavedProfileSummary>>,
    pub core: Option<NativeCoreStatus>,
    pub totals: Remote<TrafficTotals>,
    pub series: RateSeries,
    pub public_ip: Remote<PublicIpInfo>,

    pub nodes: NodesPage,
    pub latency: Latency,
    pub rules: RulesPage,

    pub connections: ConnectionsView,
    pub group_by: GroupBy,
    pub selected_group: Option<String>,
    /// What the connections search looks for; empty shows every connection.
    pub connection_search: String,
    pub sort: Option<(crate::pages::connections::SortKey, SortDirection)>,
    pub selected_connection: Option<String>,
    /// Resolved app names and icons by process key; keys being resolved.
    pub process_displays: HashMap<String, ProcessDisplay>,
    /// Counts the changes to `process_displays`, which tells the table rows
    /// built from them that they are out of date.
    pub displays_revision: u64,
    pub resolving: HashSet<String>,

    pub logs: LogsView,
    pub log_filter: LogFilter,

    /// The active profile's network settings, `None` without a profile.
    pub network: Remote<Option<ProfileNetworkSettings>>,
    pub behavior: Remote<DesktopBehaviorSettings>,
    /// A preference is being saved; changes to the others wait for it.
    pub behavior_saving: bool,
    pub log_level: Remote<LogLevel>,
    pub geodata: Remote<GeoDataStatus>,
    pub geodata_updating: bool,
    pub tun_preparing: bool,
    pub update: Update,

    pub profiles: Remote<Vec<SavedProfileSummary>>,
    /// The profile whose deletion waits for the user to confirm it.
    pub confirm_delete: Option<String>,
    /// The profile an operation runs on, and which, while it runs.
    pub profile_action: Option<(String, ProfileAction)>,
    /// The main window's open dialog.
    pub dialog: Option<Dialog>,
    /// The editor window, while it is open.
    pub editor: Option<Editor>,
}

/// Egrio's own update: the newest release, when it is newer than this
/// build, and what the check and the upgrade are doing.
#[derive(Debug, Default)]
pub struct Update {
    pub checking: bool,
    pub available: Option<egrio_desktop::updates::Release>,
    /// The last check found nothing newer.
    pub current: bool,
    /// The last check the user asked for failed.
    pub failed: bool,
    /// The installer is downloading.
    pub downloading: bool,
}

/// How long a change runs before the controls waiting for it dim: a quick
/// change ends before anything flickers.
pub const SLOW_CHANGE: std::time::Duration = std::time::Duration::from_millis(500);

/// A change the user asked for, while it runs. Its controls show what it
/// asks for from the click on; the other changes wait for it.
#[derive(Debug, Clone, PartialEq)]
pub struct Running {
    pub change: Change,
    /// Tells the timer that marks it slow which change it timed.
    pub id: u64,
    /// It has run for [`SLOW_CHANGE`]: the controls waiting for it dim.
    pub slow: bool,
}

/// A capture switch, or a change to the active profile's configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Capture {
        layer: CaptureLayer,
        enabled: bool,
    },
    /// The layers the user left on, turned back on at launch.
    Restore(CaptureLayers),
    Mode(TrafficPolicyMode),
    GlobalOutbound(String),
    /// A Select group's member, by the group's id and the member's name.
    Member {
        group_id: String,
        member: String,
    },
    Network {
        setting: ProfileNetworkSetting,
        enabled: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileAction {
    Apply,
    Rename,
    Reapply,
    Delete,
}

/// A dialog and its draft.
#[derive(Debug, Clone, PartialEq)]
pub enum Dialog {
    AddProfile(AddProfile),
    Rule(RuleDraft),
}

/// The port the Core listens on instead of the profile's, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortFallback {
    pub requested: u16,
    pub actual: u16,
    pub cause: PortUnavailable,
}

impl PortFallback {
    /// Why the profile's port could not be used.
    pub fn detail(&self, text: Text) -> String {
        match self.cause {
            PortUnavailable::InUse => text.port_in_use(self.requested),
            PortUnavailable::Reserved => text.port_reserved(self.requested),
        }
    }
}

fn port_of(address: &str) -> Option<u16> {
    address.rsplit_once(':')?.1.parse().ok()
}

impl State {
    pub fn new(lang: Lang) -> Self {
        Self {
            lang,
            section: Section::Activity,
            drawer_open: false,
            messages: MessageLog::default(),
            capture: None,
            change: None,
            active_profile: Remote::Loading,
            core: None,
            totals: Remote::Loading,
            series: RateSeries::default(),
            public_ip: Remote::Loading,
            nodes: NodesPage::default(),
            latency: Latency::default(),
            rules: RulesPage::default(),
            connections: ConnectionsView::default(),
            group_by: GroupBy::None,
            selected_group: None,
            connection_search: String::new(),
            sort: None,
            selected_connection: None,
            process_displays: HashMap::new(),
            displays_revision: 0,
            resolving: HashSet::new(),
            logs: LogsView::default(),
            log_filter: LogFilter::All,
            network: Remote::Loading,
            behavior: Remote::Loading,
            behavior_saving: false,
            log_level: Remote::Loading,
            geodata: Remote::Loading,
            geodata_updating: false,
            tun_preparing: false,
            update: Update::default(),
            profiles: Remote::Loading,
            confirm_delete: None,
            profile_action: None,
            dialog: None,
            editor: None,
        }
    }

    pub fn text(&self) -> Text {
        Text(self.lang)
    }

    /// No profile to run: the capture layers and the mode wait for one.
    pub fn needs_profile(&self) -> bool {
        matches!(self.active_profile, Remote::Ready(None))
    }

    /// A capture switch or a profile configuration change runs; the others
    /// wait for it.
    pub fn transition_pending(&self) -> bool {
        self.change.is_some()
    }

    /// The running change has taken long enough that the controls waiting
    /// for it dim.
    pub fn transition_slow(&self) -> bool {
        self.change.as_ref().is_some_and(|running| running.slow)
    }

    fn changing(&self) -> Option<&Change> {
        self.change.as_ref().map(|running| &running.change)
    }

    /// The layers a running capture switch or restore changes.
    pub fn changing_layers(&self) -> CaptureLayers {
        match self.changing() {
            Some(Change::Capture { layer, .. }) => CaptureLayers::NONE.with(*layer, true),
            Some(Change::Restore(layers)) => *layers,
            _ => CaptureLayers::NONE,
        }
    }

    /// Whether the layer's switches show it on: as the status has it, or as
    /// a switch or restore changing it asks.
    pub fn layer_on(&self, layer: CaptureLayer) -> bool {
        let on = self
            .capture
            .as_ref()
            .is_some_and(|status| status.layers.get(layer));
        match self.changing() {
            Some(Change::Capture {
                layer: changing,
                enabled,
            }) if *changing == layer => *enabled,
            Some(Change::Restore(layers)) => on || layers.get(layer),
            _ => on,
        }
    }

    /// The traffic mode the controls show for `profile`, the active one.
    pub fn mode(&self, profile: &SavedProfileSummary) -> TrafficPolicyMode {
        match self.changing() {
            Some(Change::Mode(mode)) => *mode,
            _ => profile.traffic_policy_mode,
        }
    }

    /// The Global mode outbound the controls show for `profile`.
    pub fn global_outbound<'a>(&'a self, profile: &'a SavedProfileSummary) -> Option<&'a str> {
        match self.changing() {
            Some(Change::GlobalOutbound(outbound)) => Some(outbound),
            _ => profile.global_outbound.as_deref(),
        }
    }

    /// The member a running change chooses for the Select group with
    /// `group_id`.
    pub fn choosing(&self, group_id: &str) -> Option<&str> {
        match self.changing() {
            Some(Change::Member {
                group_id: changing,
                member,
            }) if changing == group_id => Some(member),
            _ => None,
        }
    }

    /// Whether a network setting's switch shows it on, given its value in
    /// the profile.
    pub fn network_on(&self, setting: ProfileNetworkSetting, saved: bool) -> bool {
        match self.changing() {
            Some(Change::Network {
                setting: changing,
                enabled,
            }) if *changing == setting => *enabled,
            _ => saved,
        }
    }

    /// The port the Core listens on instead of the profile's, when it could
    /// not use the profile's.
    pub fn port_fallback(&self) -> Option<PortFallback> {
        let core = self.core.as_ref()?;
        let fallback = core.listener_fallback.as_ref()?;
        Some(PortFallback {
            requested: port_of(&fallback.requested)?,
            actual: port_of(core.listen_addr.as_deref()?)?,
            cause: fallback.cause,
        })
    }
}
