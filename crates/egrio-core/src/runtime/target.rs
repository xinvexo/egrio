//! Business destinations. A proxy is handed the destination as the client
//! named it, and the node resolves a name: the node connects to the target,
//! so its answer is the one that fits where it is, while an answer from this
//! network can be polluted, slow to come or a fake IP. A name the hosts map
//! is the exception: the proxy is handed the address it maps to. DIRECT
//! connects from here, so it alone resolves here, with the
//! profile's DNS, and races the candidates.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::time::Instant;

use crate::dns::service::QueryPurpose;
use crate::egress::dial::{race_connections, AttemptError, RaceFailure};
use crate::egress::{EgressBinding, EgressRuntime};
use crate::outbound::{
    write_early_data, BoxedOutboundStream, OutboundConnector, OutboundError, OutboundStage,
};
use crate::target::ConnectTarget;
use crate::tcp_flow::TcpFlowFailure;

/// Per-operation evidence: DNS failures and local policy refusals cannot mark
/// the selected proxy unhealthy when no connection to it was attempted.
#[derive(Default)]
pub(super) struct DialEvidence(AtomicBool);

impl DialEvidence {
    pub(super) fn attempted(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

pub(super) async fn connect(
    egress: &EgressRuntime,
    connector: &dyn OutboundConnector,
    target: &ConnectTarget,
    early_data: &[u8],
    deadline: Instant,
    evidence: &DialEvidence,
) -> Result<(BoxedOutboundStream, EgressBinding), TcpFlowFailure> {
    egress
        .validate_outbound_target(target, connector.is_direct())
        .map_err(TcpFlowFailure::PolicyRejected)?;
    if target.ip().is_some() || !connector.is_direct() {
        let mapped = (!connector.is_direct())
            .then(|| egress.hosts_target(target))
            .flatten();
        let target = mapped.as_ref().unwrap_or(target);
        return connect_one(egress, connector, target, early_data, evidence)
            .await
            .map_err(TcpFlowFailure::from);
    }
    let candidates = egress
        .resolve_candidates(&target.host, target.port, QueryPurpose::DirectTarget)
        .map_err(|error| OutboundError::new(OutboundStage::Local, error))?;
    // Each candidate owns its recorder and stream. Losing candidates have
    // never received client bytes; dropping them cannot replay a request.
    let (_, (mut stream, binding)) = race_connections(candidates, deadline, |address| {
        let numeric = ConnectTarget {
            host: address.ip().to_string(),
            port: target.port,
        };
        async move {
            connect_one(egress, connector, &numeric, &[], evidence)
                .await
                .map_err(TargetAttempt)
        }
    })
    .await
    .map_err(target_failure)?;
    // The target is confirmed: a failure now is the connection to it closing.
    write_early_data(&mut stream, early_data)
        .await
        .map_err(|error| OutboundError::new(OutboundStage::Target, error.to_string()))?;
    Ok((stream, binding))
}

async fn connect_one(
    egress: &EgressRuntime,
    connector: &dyn OutboundConnector,
    target: &ConnectTarget,
    early_data: &[u8],
    evidence: &DialEvidence,
) -> Result<(BoxedOutboundStream, EgressBinding), OutboundError> {
    egress
        .validate_outbound_target(target, connector.is_direct())
        .map_err(|reason| OutboundError::new(OutboundStage::Local, reason.to_string()))?;
    let recording = egress
        .socket_guard()
        .map(|_| egress.with_binding_recorder());
    let egress = recording.as_ref().unwrap_or(egress);
    evidence.0.store(true, Ordering::Relaxed);
    let stream = connector.connect_stream(egress, target, early_data).await?;
    Ok((stream, egress.recorded_binding()))
}

/// One DIRECT attempt at one target address.
struct TargetAttempt(OutboundError);

impl fmt::Display for TargetAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl AttemptError for TargetAttempt {}

/// The failure across every DIRECT target address: no address to try, only
/// local refusals, or else the target.
fn target_failure(failure: RaceFailure<TargetAttempt>) -> OutboundError {
    let stage = if failure.launched == 0 {
        OutboundStage::TargetResolve
    } else if failure.only_local(|TargetAttempt(error)| error.stage == OutboundStage::Local) {
        OutboundStage::Local
    } else {
        OutboundStage::Target
    };
    OutboundError::new(stage, failure.to_string())
}

#[cfg(test)]
mod tests;
