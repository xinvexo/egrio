use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub(crate) fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NativeCoreState {
    Stopped,
    Running,
    Stopping,
    Failed,
}

/// Why a requested listener port could not be used.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PortUnavailable {
    /// Another program already listens on it.
    InUse,
    /// The system reserves it, or another program holds it exclusively.
    Reserved,
}

/// The listener took another port because the requested one was unusable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListenerFallback {
    /// The address the host asked for.
    pub requested: String,
    pub cause: PortUnavailable,
    /// The operating system's error, for the details.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeCoreStatus {
    pub state: NativeCoreState,
    pub listen_addr: Option<String>,
    /// Set while the listener serves on another port than the one asked for.
    #[serde(default)]
    pub listener_fallback: Option<ListenerFallback>,
    pub dns_listen_addr: Option<String>,
    pub started_at_unix: Option<i64>,
    pub updated_at_unix: i64,
    pub active_sessions: u64,
    pub accepted_sessions: u64,
    pub completed_sessions: u64,
    pub failed_sessions: u64,
    pub last_error: Option<String>,
}

impl NativeCoreStatus {
    pub(crate) fn stopped() -> Self {
        Self {
            state: NativeCoreState::Stopped,
            listen_addr: None,
            listener_fallback: None,
            dns_listen_addr: None,
            started_at_unix: None,
            updated_at_unix: now_unix(),
            active_sessions: 0,
            accepted_sessions: 0,
            completed_sessions: 0,
            failed_sessions: 0,
            last_error: None,
        }
    }
}
