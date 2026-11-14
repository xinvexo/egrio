//! Everything that changes the interface state: the user's actions, timers,
//! the backend's events and the results of the operations the runtime ran.

use egrio_core::RouteEvaluation;
use egrio_core::TrafficPolicyMode;
use egrio_desktop::desktop_behavior::{
    DesktopBehaviorSettings, LanguagePreference, ThemePreference,
};
use egrio_desktop::events::DesktopEvent;
use egrio_desktop::geodata::{GeoDataStatus, GeoDataUpdateReport};
use egrio_desktop::logging::LogLevel;
use egrio_desktop::models::{ProfileRuleList, PublicIpInfo, SavedProfileSummary};
use egrio_desktop::operations::capture::{
    CaptureLayersReport, CaptureRestoreReport, CaptureStatus,
};
use egrio_desktop::operations::profiles::GroupMembers;
use egrio_desktop::operations::profiles::ProfileUpdateReport;
use egrio_desktop::profile_configuration::ProfileConfigurationUpdateReport;
use egrio_desktop::profile_network_settings::{ProfileNetworkSetting, ProfileNetworkSettings};
use egrio_desktop::rule_provider_fetch::{RuleProviderRefreshReport, RuleProviderUpdateReport};
use egrio_desktop::tun_environment::TunEnvironment;
use egrio_platform::{CaptureLayer, CaptureLayers, ProcessDisplayIdentity, ProcessDisplayQuery};

use std::path::PathBuf;
use std::sync::Arc;

use egrio_desktop::profile_source::YamlProblem;
use egrio_desktop::profile_store::ProfileSourceDocument;

use crate::latency::ProbeTarget;
use crate::node::SortDirection;
use crate::pages::logs::LogFilter;
use crate::pages::nodes::Inventory;
use crate::state::{GroupBy, Section};

#[derive(Debug, Clone)]
pub enum Msg {
    Navigate(Section),
    ToggleDrawer,
    CloseDrawer,
    ClearMessages,
    ShowMainWindow,
    MainWindowClosed,
    Quit,
    /// The quit's cleanup finished: the process may end.
    ExitReady,
    ToggleCapture(CaptureLayer),
    RetryPreparation,
    SetTrafficPolicy(TrafficPolicyMode),
    /// Choose a Select group's member in the active profile.
    SelectMember {
        group_id: String,
        member: String,
    },
    MemberSelected(Result<ProfileConfigurationUpdateReport, String>),
    Nodes(NodesMsg),
    Rules(RulesMsg),
    Connections(ConnectionsMsg),
    Logs(LogsMsg),
    Settings(SettingsMsg),
    Update(UpdateMsg),
    Profiles(ProfilesMsg),
    Editor(EditorMsg),
    /// Closes the open dialog, unless work it started is running.
    CloseDialog,

    /// Read the traffic volume for the chart.
    SampleTraffic,
    /// Read what the shown page polls every two seconds.
    PollTelemetry,
    /// Read the new log records, every second while the logs page shows.
    PollLogs,
    /// Re-read the state that events normally keep current.
    PollState,

    Desktop(DesktopEvent),

    CaptureStatus(CaptureStatus),
    ActiveProfile(Result<Option<SavedProfileSummary>, String>),
    /// Boxed: the lookup's answer is much larger than every other message.
    PublicIp(Box<Result<PublicIpInfo, String>>),
    ProcessIdentities {
        queries: Vec<ProcessDisplayQuery>,
        identities: Vec<ProcessDisplayIdentity>,
    },
    CaptureChanged(Result<CaptureLayersReport, String>),
    /// The layers the user left on when the app last ran.
    CaptureRemembered(CaptureLayers),
    CaptureRestored(Result<CaptureRestoreReport, String>),
    PolicyChanged(Result<ProfileConfigurationUpdateReport, String>),
    /// The change with this id has run for [`crate::state::SLOW_CHANGE`].
    ChangeSlow(u64),
    /// A latency test's result.
    Measured {
        target: ProbeTarget,
        result: Result<u32, String>,
    },
}

/// The nodes page's actions and reads.
#[derive(Debug, Clone)]
pub enum NodesMsg {
    /// Show a listed entry, by its key.
    Show(String),
    /// Test everything an entry lists, by its key.
    TestEntry(String),
    /// Test a member, by its name: a node itself, a group the nodes it
    /// reaches.
    TestMember(String),
    /// Test the nodes a policy group reaches, by the group's id.
    TestGroup(String),
    SetGlobalOutbound(String),
    GlobalOutboundSet(Result<ProfileConfigurationUpdateReport, String>),
    Loaded(Result<Inventory, String>),
    /// The members a profile's groups use, by group id.
    Members {
        profile_id: String,
        result: Result<GroupMembers, String>,
    },
}

/// The rules page's actions, its dialog's and route test's, and their
/// results.
#[derive(Debug, Clone)]
pub enum RulesMsg {
    Loaded {
        profile_id: String,
        result: Result<ProfileRuleList, String>,
    },
    Filter(String),
    /// The table's selection, by rule id.
    Select(Vec<String>),
    /// Edit a rule, by id.
    Edit(String),
    Add,
    Delete,
    Deleted(Result<(), String>),
    /// Rules dragged before the row at `to` of the order shown.
    Move {
        keys: Vec<String>,
        to: usize,
    },
    Moved(Result<(), String>),
    RefreshProviders,
    ProvidersRefreshed(Result<RuleProviderRefreshReport, String>),
    ProviderFetched(Result<RuleProviderUpdateReport, String>),
    ResetHits,
    RouteTarget(String),
    TestRoute,
    RouteTested {
        target: String,
        result: Box<Result<RouteEvaluation, String>>,
    },
    DraftKind(String),
    DraftPayload(String),
    DraftOutbound(String),
    DraftNoResolve(bool),
    /// Ask for the program a process rule names.
    PickExecutable,
    ExecutableChosen(Option<PathBuf>),
    Save,
    Saved {
        /// The rule set to download now that a rule names it.
        fetch: Option<String>,
        result: Result<(), String>,
        added: bool,
    },
}

#[derive(Debug, Clone)]
pub enum ConnectionsMsg {
    GroupBy(GroupBy),
    SelectGroup(String),
    /// The search field's new text.
    Search(String),
    /// The table's selection: one connection whose details show, or none.
    Select(Option<String>),
    Sort(Option<(usize, SortDirection)>),
    Clear,
}

#[derive(Debug, Clone)]
pub enum LogsMsg {
    Filter(LogFilter),
    Clear,
}

/// The settings page's actions and the results of its reads and writes.
#[derive(Debug, Clone)]
pub enum SettingsMsg {
    PrepareTun,
    TunPrepared(TunEnvironment),
    SetNetwork(ProfileNetworkSetting, bool),
    NetworkChanged(Result<ProfileConfigurationUpdateReport, String>),
    Network(Result<Option<ProfileNetworkSettings>, String>),
    SetAutostart(bool),
    SetSilentStart(bool),
    SetCheckUpdates(bool),
    SetTheme(ThemePreference),
    SetLanguage(LanguagePreference),
    Behavior(Result<DesktopBehaviorSettings, String>),
    BehaviorSaved(SavedSetting, Result<DesktopBehaviorSettings, String>),
    SetLogLevel(LogLevel),
    LogLevelSaved(Result<LogLevel, String>),
    LogLevel(Result<LogLevel, String>),
    UpdateGeodata,
    GeodataUpdated(Result<GeoDataUpdateReport, String>),
    Geodata(Result<GeoDataStatus, String>),
}

/// Egrio's own update: the check, at launch or asked for, and the upgrade.
#[derive(Debug, Clone)]
pub enum UpdateMsg {
    /// `asked`: the user asked, so the answer shows in place and a failure
    /// is a message; the check at launch reports only a newer version.
    Check {
        asked: bool,
    },
    Checked {
        asked: bool,
        result: Result<Option<egrio_desktop::updates::Release>, String>,
    },
    Upgrade,
    Downloaded(Result<std::path::PathBuf, String>),
}

/// Which preference a save was for, which names its failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedSetting {
    Startup,
    Theme,
    Language,
}

/// The profiles page's actions, its add dialog's, and their results.
#[derive(Debug, Clone)]
pub enum ProfilesMsg {
    Loaded(Result<Vec<SavedProfileSummary>, String>),
    Apply(String),
    Applied(Result<ProfileUpdateReport, String>),
    Rename(String, String),
    Renamed(Result<SavedProfileSummary, String>),
    Reapply(String),
    Reapplied(Result<ProfileConfigurationUpdateReport, String>),
    AskDelete(String),
    CancelDelete,
    Delete {
        id: String,
        stop_if_active: bool,
    },
    Deleted(Result<(), String>),
    OpenAdd,
    AddName(String),
    AddUrl(String),
    Download,
    ChooseFile,
    FileChosen(Option<PathBuf>),
    /// Closes the add dialog for the editor with a new profile's template.
    NewBlank,
    Imported(Result<SavedProfileSummary, ImportFailure>),
}

/// Why an import from the add dialog failed.
#[derive(Debug, Clone)]
pub enum ImportFailure {
    Download(String),
    ReadFile(String),
    Import(String),
}

/// The editor window's actions and the results of its reads, checks and
/// saves; a result names the editor it is for, since the editor may have
/// closed and another opened while it ran.
#[derive(Debug, Clone)]
pub enum EditorMsg {
    /// Edit a saved profile.
    Edit {
        id: String,
        name: String,
    },
    /// Write a new profile, under `name`, from the template.
    New {
        name: String,
    },
    Loaded {
        instance: u64,
        result: Result<ProfileSourceDocument, String>,
    },
    /// The text editor's new text.
    Changed(String),
    Checked {
        instance: u64,
        revision: u64,
        problem: Option<YamlProblem>,
    },
    Save,
    Saved {
        instance: u64,
        yaml: Arc<str>,
        result: Result<EditorSave, String>,
    },
    Revert,
    /// Show where the first error is.
    ShowProblem,
    Close,
}

/// A saved editor's profile, and how its running configuration took the
/// change (`None` for a new profile).
#[derive(Debug, Clone)]
pub struct EditorSave {
    pub profile: SavedProfileSummary,
    pub application: Option<ProfileConfigurationUpdateReport>,
}
