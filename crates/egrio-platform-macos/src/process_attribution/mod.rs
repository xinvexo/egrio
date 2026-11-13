//! macOS flow ownership, independent of TUN control and Core.
//! Observations describe current same-UID connections, not authenticated sender
//! identity. Ambiguous, shared or incomplete observations remain unknown.
mod native;

use egrio_core::{FlowKey, FlowProtocol, FlowScanner, ProcessInfo};
use native::{FlowCandidate, ScanReport, Source};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Core's attribution worker calls this with batches of raw capture tuples;
/// one bounded socket scan, plus a userland-flow pass for the flows it left
/// unowned, answers the whole batch within one budget.
#[derive(Debug, Default)]
pub struct MacosFlowScanner {
    last_diagnostic: Mutex<Option<Instant>>,
}

impl FlowScanner for MacosFlowScanner {
    fn scan(
        &self,
        flows: &[FlowKey],
        budget: Duration,
        stop: &AtomicBool,
    ) -> Vec<Option<ProcessInfo>> {
        let started = Instant::now();
        let attribution = attribute(flows, |source, requests| {
            native::scan(
                source,
                requests,
                budget.saturating_sub(started.elapsed()),
                stop,
            )
        });
        if let Some((source, report)) = &attribution.incomplete {
            self.diagnose(*source, report);
        }
        attribution.owners
    }
}

impl MacosFlowScanner {
    /// Incomplete scans are expected (other users, races, budgets); log at
    /// most one summary every ten seconds.
    fn diagnose(&self, source: Source, report: &ScanReport) {
        let now = Instant::now();
        let mut last = self
            .last_diagnostic
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|last| now.duration_since(last) < Duration::from_secs(10)) {
            return;
        }
        *last = Some(now);
        log::debug!("macOS process attribution {source:?} scan incomplete: pids={} fds={} userland_flows={} denied={} races={} errors={} limited={} timeout={} cancelled={} unsupported={} elapsed_us={}",
            report.pids_scanned, report.fds_scanned, report.userland_flows, report.permission_denied, report.raced,
            report.syscall_errors, report.limited, report.timed_out, report.cancelled, report.unsupported, report.elapsed.as_micros());
    }
}

struct Attribution {
    owners: Vec<Option<ProcessInfo>>,
    /// The source whose observation was discarded, for diagnostics.
    incomplete: Option<(Source, ScanReport)>,
}

/// Socket descriptors decide whether the batch is answerable at all: any doubt
/// about them leaves every flow unknown. The kernel's userland-flow snapshot
/// is private and may be hidden or unavailable, so it is consulted only for
/// flows that no socket matched. Its rows were verified one by one; when the
/// snapshot as a whole is unusable, exactly those flows stay unknown.
fn attribute(
    flows: &[FlowKey],
    mut scan: impl FnMut(Source, &[FlowKey]) -> ScanReport,
) -> Attribution {
    let sockets = scan(Source::Sockets, flows);
    if !sockets.complete {
        return Attribution {
            owners: flows.iter().map(|_| None).collect(),
            incomplete: Some((Source::Sockets, sockets)),
        };
    }
    let mut candidates = sockets.candidates;
    let unowned = flows
        .iter()
        .filter(|flow| {
            !candidates
                .iter()
                .any(|candidate| endpoint_matches(candidate, flow))
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut incomplete = None;
    if !unowned.is_empty() {
        let userland = scan(Source::UserlandFlows, &unowned);
        if userland.complete {
            candidates.extend(userland.candidates);
        } else {
            incomplete = Some((Source::UserlandFlows, userland));
        }
    }
    Attribution {
        owners: flows
            .iter()
            .map(|flow| resolve(flow, &candidates))
            .collect(),
        incomplete,
    }
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn endpoint_matches(candidate: &FlowCandidate, flow: &FlowKey) -> bool {
    if candidate.protocol != flow.protocol || candidate.local_endpoint.port() != flow.source_port {
        return false;
    }
    let local = candidate.local_endpoint.ip();
    let local_matches = (same_family(local, flow.source_ip)
        && (local.is_unspecified() || local == flow.source_ip))
        || (candidate.dual_stack && local.is_unspecified());
    if !local_matches {
        return false;
    }
    match candidate.remote_endpoint {
        Some(remote) => remote == SocketAddr::new(flow.destination_ip, flow.destination_port),
        None => flow.protocol == FlowProtocol::Udp,
    }
}

/// Candidates come only from complete observations.
fn resolve(flow: &FlowKey, candidates: &[FlowCandidate]) -> Option<ProcessInfo> {
    let mut owner: Option<&FlowCandidate> = None;
    for candidate in candidates
        .iter()
        .filter(|candidate| endpoint_matches(candidate, flow))
    {
        if candidate.shared
            || candidate.dual_stack
            || candidate.pid == 0
            || candidate.owner_pid == 0
            || !candidate.executable.is_absolute()
            || (flow.protocol == FlowProtocol::Udp
                && (candidate.reuse_addr || candidate.reuse_port))
        {
            return None;
        }
        if let Some(previous) = owner {
            if (
                previous.pid,
                previous.owner_pid,
                previous.userland,
                previous.start_sec,
                previous.start_usec,
                previous.socket_id,
                previous.socket_generation,
                &previous.executable,
            ) != (
                candidate.pid,
                candidate.owner_pid,
                candidate.userland,
                candidate.start_sec,
                candidate.start_usec,
                candidate.socket_id,
                candidate.socket_generation,
                &candidate.executable,
            ) {
                return None;
            }
        } else {
            owner = Some(candidate);
        }
    }
    let owner = owner?;
    let path = owner.executable.to_str()?.to_owned();
    let name = owner.executable.file_name()?.to_str()?.to_owned();
    Some(ProcessInfo {
        name: Some(name),
        path: Some(path),
    })
}

#[cfg(test)]
mod tests;
