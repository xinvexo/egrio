//! Core status, traffic telemetry and connection display commands.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::connection_history::{ConnectionHistory, ConnectionsUpdate, TrafficTotals};
use crate::runtime::DesktopRuntime;
use egrio_core::NativeCoreStatus;
use serde::Serialize;

/// Display-only enrichment for the connections table: resolves process
/// identities into app display names and icons. Platform-dispatched —
/// macOS resolves attributed executable paths through Foundation/AppKit;
/// Windows extracts the icon from the executable path the
/// capture layer attributed (`query.path`); platforms without a resolver echo
/// the identifiers back so the UI keeps its raw-identifier fallback. Each
/// query's `identifier` is preserved as the answer key regardless of platform.
pub async fn resolve_process_display_identities(
    requests: Vec<egrio_platform::ProcessDisplayQuery>,
) -> Result<Vec<egrio_platform::ProcessDisplayIdentity>, String> {
    #[cfg(target_os = "macos")]
    {
        // Native file/bundle lookups and icon encoding run on a blocking
        // worker. Preserve query order, identifier and executable path.
        crate::async_runtime::spawn_blocking(move || {
            egrio_platform_macos::resolve_app_display_identities(&requests)
        })
        .await
        .map_err(|error| format!("identity resolution task failed: {error}"))?
    }
    #[cfg(target_os = "windows")]
    {
        // Windows extracts the icon from the executable path via SHGetFileInfo
        // + GDI, which are synchronous; keep them off the async runtime.
        crate::async_runtime::spawn_blocking(move || {
            egrio_platform_windows::resolve_app_display_identities(&requests)
        })
        .await
        .map_err(|error| format!("identity resolution task failed: {error}"))
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        Ok(requests
            .into_iter()
            .map(|request| egrio_platform::ProcessDisplayIdentity::unresolved(request.identifier))
            .collect())
    }
}

pub fn native_core_status(runtime: &DesktopRuntime) -> NativeCoreStatus {
    runtime
        .core_status()
        .unwrap_or_else(stopped_native_core_status)
}

/// The connection table's poll: what changed in the history since the
/// revision the table holds, or every row when it holds none.
pub fn traffic_connections(
    history: &Mutex<ConnectionHistory>,
    since: Option<u64>,
) -> ConnectionsUpdate {
    history
        .lock()
        .expect("connection history mutex")
        .changes_since(since)
}

/// The history's figures without its rows, for the activity page.
pub fn traffic_totals(history: &Mutex<ConnectionHistory>) -> TrafficTotals {
    history.lock().expect("connection history mutex").totals()
}

/// The rules page's hit counts: connections per rule of `profile_id`, each
/// rule named as the profile writes it.
pub fn rule_hits(history: &Mutex<ConnectionHistory>, profile_id: &str) -> HashMap<String, u64> {
    history
        .lock()
        .expect("connection history mutex")
        .rule_hits(profile_id)
}

pub fn reset_rule_hits(history: &Mutex<ConnectionHistory>, profile_id: &str) {
    history
        .lock()
        .expect("connection history mutex")
        .reset_rule_hits(profile_id);
}

/// One reading of the running Core's traffic volume, for the rate chart.
#[derive(Debug, Clone, Serialize)]
pub struct TrafficVolumeSample {
    /// When it was read, in milliseconds on a monotonic clock that starts
    /// with the app. Rates divide by the difference of two readings' stamps,
    /// which carry none of the IPC round trip's jitter.
    pub at_ms: f64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

/// The rate chart's poll: the running Core's traffic volume, `None` while no
/// Core runs. It reads two counters, so the chart polls it several times a
/// second; the connection history keeps its own, slower poll.
pub fn traffic_volume(runtime: &DesktopRuntime) -> Option<TrafficVolumeSample> {
    runtime.traffic_volume().map(|volume| TrafficVolumeSample {
        at_ms: monotonic_ms(),
        upload_bytes: volume.upload_bytes,
        download_bytes: volume.download_bytes,
    })
}

fn monotonic_ms() -> f64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_secs_f64() * 1000.0
}

/// How often the history takes in the Core's rows.
const HISTORY_POLL: Duration = Duration::from_secs(2);

/// Keeps the connection history current for the app's lifetime, whether a
/// window shows or not: the Core keeps only live tables and a bounded ring of
/// terminal records, so a history that waited for a window to ask would lose
/// the connections that finished meanwhile.
pub async fn absorb_connection_history(
    runtime: DesktopRuntime,
    history: Arc<Mutex<ConnectionHistory>>,
) {
    let mut poll = tokio::time::interval(HISTORY_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        poll.tick().await;
        let cursor = history.lock().expect("connection history mutex").cursor();
        let profile = runtime.running_profile_id();
        let (connections, sampled_at_unix, cursor) = match runtime
            .traffic_telemetry_since(cursor)
            .await
        {
            Some((snapshot, cursor)) => (snapshot.connections, snapshot.sampled_at_unix, cursor),
            None => (Vec::new(), now_unix(), Default::default()),
        };
        let mut history = history.lock().expect("connection history mutex");
        history.set_profile(profile);
        history.absorb(connections, sampled_at_unix);
        history.set_cursor(cursor);
    }
}

/// The connection page's clear button: drops finished (completed and
/// failed) history rows, keeps active ones, and returns how many were
/// removed.
pub fn clear_finished_connections(history: &Mutex<ConnectionHistory>) -> usize {
    history
        .lock()
        .expect("connection history mutex")
        .clear_finished(now_unix())
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub fn stopped_native_core_status() -> NativeCoreStatus {
    NativeCoreStatus {
        state: egrio_core::NativeCoreState::Stopped,
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
