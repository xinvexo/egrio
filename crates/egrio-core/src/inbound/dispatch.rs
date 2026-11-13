//! The dispatcher: the fixed enrich → route → dial → relay
//! pipeline every accepted session rides. Acceptors produce sessions;
//! nothing here can name a wire protocol — protocol
//! replies arrive as data in the session's `InboundReplyPlan`, and the
//! IO is any duplex stream, so an acceptor-produced decrypting wrapper
//! relays exactly like a plaintext socket.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::attribution::ClientOwner;
use crate::device::NativeTcpFlowOutcome;
use crate::inbound::acceptor::{
    AcceptedDatagramFace, AcceptedStream, InboundAcceptor, InboundSession,
};
use crate::protocols::http::HttpProxyAcceptor;
use crate::protocols::socks5::Socks5Acceptor;
use crate::relay::{relay_registered_session, RELAY_IDLE_TIMEOUT};
use crate::runtime::{
    open_outbound_connection_for_session, tcp_route_match_input, NativeCoreRuntime,
};
use crate::session_registry::{SessionGuard, SessionPhase};
use crate::sniff::sniff_stream_first_data;
use crate::target::ConnectTarget;
use crate::tcp_flow::{
    NativeTcpFlowError, TcpFlowContext, TcpFlowFailure, TcpFlowIoAction, TcpFlowIoSide,
    TcpFlowStage,
};
use crate::udp::{drain_udp_face_responses, send_udp_flow_datagram, UdpDatagram};
use crate::ConnectionTermination;

/// Terminal facts survive dispatch until the listener accounts for them.
/// Protocol diagnostics that are still textual remain failures; only an
/// explicit cancellation or a typed TCP cause can classify an expected end.
#[derive(Debug)]
pub(crate) enum InboundSessionError {
    Cancelled,
    Handshake(String),
    Tcp(NativeTcpFlowError),
    Datagrams(String),
}

impl InboundSessionError {
    pub(crate) fn termination(&self) -> ConnectionTermination {
        match self {
            Self::Cancelled => ConnectionTermination::Cancelled,
            Self::Tcp(error) => ConnectionTermination::from_failure(error.stage, &error.cause),
            Self::Handshake(message) => ConnectionTermination::from_failure(
                TcpFlowStage::Admission,
                &TcpFlowFailure::Message(message.clone()),
            ),
            Self::Datagrams(message) => ConnectionTermination::from_failure(
                TcpFlowStage::Relay,
                &TcpFlowFailure::Message(message.clone()),
            ),
        }
    }
}

impl std::fmt::Display for InboundSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("inbound session cancelled"),
            Self::Handshake(message) | Self::Datagrams(message) => message.fmt(f),
            Self::Tcp(error) => error.fmt(f),
        }
    }
}

#[derive(Debug)]
pub(crate) struct InboundSessionOutcome {
    pub(crate) termination: ConnectionTermination,
}

/// The enrich stage for one session, cheapest link first:
/// a fake-IP reverse hit replaces the unroutable fake IP end to end;
/// otherwise, a first-flight sniff can recover an unmapped fake IP or refine
/// routing when a reachable rule could use a domain. A domain target skips
/// the stage entirely.
pub(crate) struct EnrichedTarget {
    /// Target to dial: a fake IP must be replaced by its recovered domain.
    pub(crate) dial_target: ConnectTarget,
    /// Domain for the routing decision, when the raw target had none.
    pub(crate) route_host: Option<String>,
    /// Client bytes the sniff consumed; forwarded ahead of the relay.
    pub(crate) early_data: Vec<u8>,
    /// Whether `success_reply` was already written: the client only sends
    /// the first flight a sniff waits for after the inbound reports success,
    /// so a sniffing handler must not reply a second time (nor can it still
    /// deliver a protocol error).
    pub(crate) replied_early: bool,
}

pub(crate) async fn enrich_ip_target<S>(
    runtime: &NativeCoreRuntime,
    client: &mut S,
    target: &ConnectTarget,
    session: &SessionGuard,
    success_reply: &[u8],
) -> Result<EnrichedTarget, TcpFlowFailure>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + ?Sized,
{
    let mut enriched = EnrichedTarget {
        dial_target: target.clone(),
        route_host: None,
        early_data: Vec::new(),
        replied_early: false,
    };
    let Some(ip) = target.ip() else {
        return Ok(enriched);
    };
    let mapped_domain = runtime.fake_dns_domain_for_ip(ip);
    let stale_fake_target = mapped_domain.is_none() && runtime.is_fake_range_target(ip);
    if let Some(domain) = mapped_domain {
        enriched.dial_target.host = domain.clone();
        enriched.route_host = Some(domain);
    } else if runtime.should_sniff(target)
        || (stale_fake_target && crate::sniff::is_sniffable_port(target.port))
    {
        session.set_phase(SessionPhase::Enriching);
        if !success_reply.is_empty() {
            client.write_all(success_reply).await.map_err(|error| {
                TcpFlowFailure::io(TcpFlowIoSide::Client, TcpFlowIoAction::Write, error)
            })?;
            enriched.replied_early = true;
        }
        let sniffed = sniff_stream_first_data(client, runtime.sniff_stats()).await;
        if stale_fake_target {
            if let Some(domain) = &sniffed.domain {
                enriched.dial_target.host = domain.clone();
            }
        }
        enriched.route_host = sniffed.domain;
        enriched.early_data = sniffed.prefix;
    }
    // Neither the current mapping nor the first flight named this fake IP.
    // Refuse instead of sending the virtual address to an outbound.
    if enriched.route_host.is_none() && stale_fake_target {
        return Err(TcpFlowFailure::Message(format!(
            "refusing stale fake-IP target {ip}: no mapping in this capture session"
        )));
    }
    if let Some(host) = &enriched.route_host {
        session.set_host(host);
    }
    Ok(enriched)
}

#[cfg(test)]
/// The mixed plaintext entry: runs the SOCKS5/HTTP proxy handshake, then
/// hands the accepted session to the dispatch pipeline. Returns the outbound
/// the session routed to.
pub(crate) async fn handle_connect_client(
    client: TcpStream,
    runtime: &NativeCoreRuntime,
) -> Result<String, String> {
    let source = client.peer_addr().ok().map(|addr| addr.to_string());
    let InboundSession::Stream(accepted) = accept_mixed_session(client).await? else {
        return Err("mixed CONNECT handshake produced a datagram face".into());
    };
    dispatch_accepted_stream(runtime, source, accepted)
        .await
        .map(|outcome| outcome.outbound)
        .map_err(|error| error.to_string())
}

/// Runs the mixed plaintext handshake: a first-byte peek picks the SOCKS5 or
/// HTTP CONNECT acceptor, whose handshake yields the accepted session. Split
/// from the dispatch tail so the listener can bound just the handshake with a
/// timeout while leaving the relay that follows unbounded.
pub(crate) async fn accept_mixed_session(client: TcpStream) -> Result<InboundSession, String> {
    let mut first = [0_u8; 1];
    let read = client
        .peek(&mut first)
        .await
        .map_err(|error| format!("failed to inspect inbound protocol: {error}"))?;
    if read == 0 {
        return Err("connection closed before inbound protocol detection".into());
    }
    if first[0] == 0x05 {
        Socks5Acceptor.accept(Box::new(client)).await
    } else {
        HttpProxyAcceptor.accept(Box::new(client)).await
    }
}

/// Drives one accepted session through the pipeline, whatever acceptor
/// produced it: a stream session runs the enrich → route → dial → relay
/// pipeline. A datagram face is not something a stream inbound composes, so
/// it is a protocol error here — the authenticated UDP face rides
/// [`dispatch_accepted_datagrams`] instead.
pub(crate) async fn dispatch_session(
    runtime: &NativeCoreRuntime,
    source: Option<String>,
    session: InboundSession,
) -> Result<InboundSessionOutcome, InboundSessionError> {
    match session {
        InboundSession::Stream(accepted) => dispatch_accepted_stream(runtime, source, accepted)
            .await
            .map(|outcome| InboundSessionOutcome {
                termination: if crate::rule_engine::is_reject_outbound(&outcome.outbound) {
                    ConnectionTermination::RouteRejected
                } else {
                    ConnectionTermination::Completed
                },
            })
            .map_err(InboundSessionError::Tcp),
        // An acceptor that authenticated a UDP associate (Trojan) yields a
        // datagram face instead of a stream; it rides the same no-wait pump the
        // Hysteria2 QUIC datagram face uses.
        InboundSession::Datagrams(face) => {
            dispatch_accepted_datagrams(runtime, face)
                .await
                .map(|()| InboundSessionOutcome {
                    termination: ConnectionTermination::Completed,
                })
        }
    }
}

/// Drives one accepted stream through the pipeline: admission → enrich →
/// route → dial → relay, writing the acceptor's reply bytes at each fixed
/// reply point. Returns the outbound the routing decision named.
pub(crate) async fn dispatch_accepted_stream(
    runtime: &NativeCoreRuntime,
    source: Option<String>,
    accepted: AcceptedStream,
) -> Result<NativeTcpFlowOutcome, NativeTcpFlowError> {
    let AcceptedStream {
        inbound,
        user,
        process,
        target,
        mut io,
        replies,
        mut reset,
    } = accepted;
    let mut refuse = move || {
        if let Some(reset) = reset.take() {
            reset();
        }
    };
    let target_authority = target.authority();
    let mut context = TcpFlowContext {
        target: target_authority.clone(),
        ..Default::default()
    };

    let session = match runtime.session_registry().admit(
        inbound,
        source,
        target_authority.clone(),
        runtime.epoch_membership(),
    ) {
        Ok(session) => session,
        Err(refusal) => {
            let cause = if runtime.session_registry().is_closed() {
                TcpFlowFailure::Cancelled
            } else {
                TcpFlowFailure::Message(refusal)
            };
            let _ = write_reply(&mut io, &replies.admission_refused).await;
            refuse();
            return Err(flow_error(&context, TcpFlowStage::Admission, cause, None));
        }
    };
    context.session_id = Some(session.id());
    if let Some(user) = &user {
        session.set_user(user);
    }
    let trace = relay_trace_enabled();
    let trace_started = trace.then(Instant::now);
    if trace {
        eprintln!(
            "[relay-trace] t={:.3} flow={} accept inbound={inbound} target={target_authority}",
            trace_clock(),
            session.id()
        );
    }

    let admission_cancel = runtime.connection_cancellation();
    let enriched = tokio::select! {
        biased;
        _ = admission_cancel.cancelled() => return Err(flow_error(&context, TcpFlowStage::Admission, TcpFlowFailure::Cancelled, Some(&session))),
        result = enrich_ip_target(runtime, io.as_mut(), &target, &session, &replies.success) => result
            .map_err(|cause| flow_error(&context, TcpFlowStage::Enrich, cause, Some(&session)))?,
    };
    context.route_host = enriched
        .route_host
        .clone()
        .or_else(|| target.ip().is_none().then(|| target.host.clone()));
    context.dial_target = Some(enriched.dial_target.authority());
    session.set_phase(SessionPhase::Routing);
    // A rule reading the process waits for an owner still being looked up;
    // otherwise the flow routes at once and its row takes the owner later.
    let (process, late_owner) = match process {
        ClientOwner::Known(process) => (process, None),
        ClientOwner::Pending(lookup) if runtime.routes_by_process() => tokio::select! {
            biased;
            _ = admission_cancel.cancelled() => return Err(flow_error(&context, TcpFlowStage::Route, TcpFlowFailure::Cancelled, Some(&session))),
            process = lookup.resolve() => (process, None),
        },
        ClientOwner::Pending(lookup) => (None, Some(lookup)),
    };
    let mut route_input =
        tcp_route_match_input(&enriched.dial_target, enriched.route_host.as_deref());
    if let Some(process) = process {
        route_input.process_name = process.name.clone();
        route_input.process_path = process.path.clone();
    }
    // A name an IP rule asks about resolves before routing, outside the
    // admission section, which must not wait on DNS.
    let address = tokio::select! {
        biased;
        _ = admission_cancel.cancelled() => return Err(flow_error(&context, TcpFlowStage::Route, TcpFlowFailure::Cancelled, Some(&session))),
        address = runtime.rule_address(&route_input) => address,
    };
    let (route, resolved) = runtime
        .with_route_admission(|| {
            let route = runtime.route_with_address(&route_input, address);
            let rejected = crate::rule_engine::is_reject_outbound(&route.outbound);
            let resolved = if rejected {
                None
            } else {
                runtime.resolve_outbound(&route.outbound, &enriched.dial_target)
            };
            // The connection row names the process, rule and outbound of a
            // rejected flow as well as of a dialed one.
            let routed_to = match &resolved {
                Some(resolved) if resolved.connector.supports_tcp() => Some(resolved.name.as_str()),
                None if rejected => Some(route.outbound.as_str()),
                _ => None,
            };
            if let Some(outbound) = routed_to {
                session.set_route(
                    outbound,
                    route.matched_rule.as_deref(),
                    crate::session_registry::RouteQuestion {
                        input: route_input.clone(),
                        address,
                        dial_target: enriched.dial_target.clone(),
                    },
                );
            }
            (route, resolved)
        })
        .map_err(|error| {
            flow_error(
                &context,
                TcpFlowStage::Route,
                if admission_cancel.is_cancelled() {
                    TcpFlowFailure::Cancelled
                } else {
                    TcpFlowFailure::Message(error)
                },
                Some(&session),
            )
        })?;
    if let Some(lookup) = late_owner {
        let slot = session.process_slot();
        runtime.task_tracker().spawn(async move {
            if let Some(process) = lookup.resolve_for_record().await {
                slot.fill(&process);
            }
        });
    }
    context.outbound = Some(route.outbound.clone());
    context.resolved_outbound = resolved.as_ref().map(|resolved| resolved.name.clone());
    context.matched_rule = route.matched_rule.clone();
    context.matched_kind = route.matched_kind;
    context.matched_payload = route.matched_payload.clone();

    if crate::rule_engine::is_reject_outbound(&route.outbound) {
        session.record_termination(ConnectionTermination::RouteRejected);
        if !enriched.replied_early {
            write_reply(&mut io, &replies.route_rejected)
                .await
                .map_err(|cause| {
                    flow_error(&context, TcpFlowStage::Reply, cause, Some(&session))
                })?;
        }
        refuse();
        return Ok(NativeTcpFlowOutcome {
            outbound: route.outbound,
            matched_rule: route.matched_rule,
            matched_kind: route.matched_kind,
            matched_payload: route.matched_payload,
            target: target_authority,
        });
    }

    let Some(resolved) = resolved else {
        if !enriched.replied_early {
            let _ = write_reply(&mut io, &replies.outbound_unavailable).await;
        }
        refuse();
        return Err(flow_error(
            &context,
            TcpFlowStage::Route,
            TcpFlowFailure::Message(format!(
                "native core outbound '{}' is not implemented yet",
                route.outbound
            )),
            Some(&session),
        ));
    };
    if !resolved.connector.supports_tcp() {
        if !enriched.replied_early {
            let _ = write_reply(&mut io, &replies.outbound_unavailable).await;
        }
        refuse();
        return Err(flow_error(
            &context,
            TcpFlowStage::Route,
            TcpFlowFailure::Message(format!(
                "outbound '{}' does not support TCP flows",
                route.outbound
            )),
            Some(&session),
        ));
    }
    if trace {
        eprintln!(
            "[relay-trace] t={:.3} flow={} routed outbound={} rule={:?} dial_target={} elapsed_ms={}",
            trace_clock(),
            session.id(),
            route.outbound,
            route.matched_rule,
            enriched.dial_target.authority(),
            trace_started
                .as_ref()
                .expect("relay trace start")
                .elapsed()
                .as_millis()
        );
    }

    session.set_phase(SessionPhase::Dialing);
    let upstream = open_outbound_connection_for_session(
        runtime,
        &enriched.dial_target,
        &resolved,
        &enriched.early_data,
        &session,
    )
    .await;
    if trace {
        eprintln!(
            "[relay-trace] t={:.3} flow={} dialed result={} elapsed_ms={}",
            trace_clock(),
            session.id(),
            upstream
                .as_ref()
                .map_or_else(|error| format!("err({error})"), |_| "ok".into()),
            trace_started
                .as_ref()
                .expect("relay trace start")
                .elapsed()
                .as_millis()
        );
    }
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(cause) => {
            let error = flow_error(&context, TcpFlowStage::Dial, cause, Some(&session));
            if !enriched.replied_early {
                // Preserve the primary result even if this secondary reply
                // fails or the owner task is cancelled while writing it.
                let _ = write_reply(&mut io, &replies.dial_failed).await;
            }
            // A flow no dial could carry ends as a refused connection would,
            // not as an empty answer.
            refuse();
            return Err(error);
        }
    };
    if !enriched.replied_early {
        write_reply(&mut io, &replies.success)
            .await
            .map_err(|cause| flow_error(&context, TcpFlowStage::Reply, cause, Some(&session)))?;
    }
    let relay_result = relay_registered_session(
        io.as_mut(),
        upstream,
        &session,
        enriched.early_data.len() as u64,
    )
    .await;
    if trace {
        let counters = session.byte_counters();
        eprintln!(
            "[relay-trace] t={:.3} flow={} closed result={} up={} down={} elapsed_ms={}",
            trace_clock(),
            session.id(),
            relay_result
                .as_ref()
                .map_or_else(|error| format!("err({error})"), |()| "ok".into()),
            counters.up.load(Ordering::Relaxed),
            counters.down.load(Ordering::Relaxed),
            trace_started
                .as_ref()
                .expect("relay trace start")
                .elapsed()
                .as_millis()
        );
    }
    // A relay Core itself ends, cancelled (its network gone, a kill) or out
    // of budget, is aborted toward the client, which must not take the cut
    // for the end of the data; an upstream close or failure flushes and FINs.
    if let Err(failure) = &relay_result {
        if matches!(
            failure.cause,
            TcpFlowFailure::Cancelled | TcpFlowFailure::Budget { .. }
        ) {
            refuse();
        }
    }
    relay_result.map_err(|error| {
        session.record_termination(ConnectionTermination::from_failure(
            TcpFlowStage::Relay,
            &error.cause,
        ));
        NativeTcpFlowError {
            stage: TcpFlowStage::Relay,
            context,
            upload_bytes: error.upload_bytes,
            download_bytes: error.download_bytes,
            cause: error.cause,
        }
    })?;
    session.record_termination(ConnectionTermination::Completed);

    Ok(NativeTcpFlowOutcome {
        outbound: route.outbound,
        matched_rule: route.matched_rule,
        matched_kind: route.matched_kind,
        matched_payload: route.matched_payload,
        target: target_authority,
    })
}

/// Datagram-face drain tuning: how many queued responses one drain pass
/// delivers, and how long a drain parks for a response before looping. The park
/// is woken the instant a response lands, so `MAX_WAIT` only bounds the idle
/// case.
const FACE_DRAIN_MAX_DATAGRAMS: usize = 256;
const FACE_DRAIN_MAX_WAIT: Duration = Duration::from_secs(1);
/// A face with nothing moving either way for [`RELAY_IDLE_TIMEOUT`] has lost
/// its client, so it ends. Neither half can tell on its own: the framed read
/// half parks forever when a host disappears without a FIN or an RST, and an
/// inbound socket gets no TCP keepalive, so the face would otherwise hold its
/// listener permit, its connection and a drain task waking every second for
/// as long as the process ran. Activity-based like the established relay's
/// budget, never a lifetime, so a quiet long-lived associate survives.
async fn face_idle(moved: &AtomicU64) {
    let mut seen = moved.load(Ordering::Relaxed);
    let mut changed = tokio::time::Instant::now();
    loop {
        tokio::time::sleep_until(changed + RELAY_IDLE_TIMEOUT).await;
        let now = moved.load(Ordering::Relaxed);
        if now == seen {
            return;
        }
        seen = now;
        changed = tokio::time::Instant::now();
    }
}

/// Per-face flow-id counter: the UDP session key already keys flows by user, so
/// this only keeps two connections' flow ledgers (and `close_flow`) addressable
/// apart in the rare same-user, same-source case.
static NEXT_FACE_ID: AtomicU64 = AtomicU64::new(0);

/// Aborts the wrapped task on drop, so the background drain never outlives the
/// face — including when the whole pump future is cancelled rather than ending
/// through its own path.
struct AbortOnDrop(tokio::task::JoinHandle<Result<(), String>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Closes the face's UDP sessions when the face ends, by the flow-id prefix
/// only this face mints. Aborting the drain task is not enough: the sessions
/// live in the device's table with their own actor tasks and upstream sockets,
/// and idle sweeping only runs when some other caller happens to touch the
/// table — on a TCP-only deployment that may never happen again, so
/// disconnect/reconnect churn would walk the table to its admission cap.
///
/// Runs on drop so a cancelled pump future reclaims its flows too.
struct CloseFlowsOnDrop {
    runtime: NativeCoreRuntime,
    flow_prefix: String,
}

impl Drop for CloseFlowsOnDrop {
    fn drop(&mut self) {
        self.runtime
            .udp_sessions()
            .close_flows_with_prefix(&self.flow_prefix);
    }
}

/// Pumps one authenticated datagram face on the no-wait actor path: the send
/// loop hands each deframed datagram to its session
/// actor and moves straight on — never awaiting the target — while a background
/// drain delivers responses back to their flows, so one stalled target cannot
/// head-of-line-block the connection's other flows. A datagram whose send fails
/// is dropped, not fatal (UDP loss semantics); a
/// receiver error (send side) or responder error (drain side) ends the face —
/// a framed stream cannot resync.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn dispatch_accepted_datagrams(
    runtime: &NativeCoreRuntime,
    face: AcceptedDatagramFace,
) -> Result<(), InboundSessionError> {
    let AcceptedDatagramFace {
        user,
        mut receiver,
        responder,
    } = face;
    let face_id = NEXT_FACE_ID.fetch_add(1, Ordering::Relaxed);
    // Every flow this face opens is namespaced under it, so teardown can
    // reclaim exactly its own sessions.
    let _close_flows = CloseFlowsOnDrop {
        runtime: runtime.clone(),
        flow_prefix: format!("udp-face/{face_id}/"),
    };
    // Datagrams this face moved either way, which its idle budget reads.
    let moved = Arc::new(AtomicU64::new(0));

    // The background drain owns the responder for the face's whole life,
    // scoped to the face's `user` so it never drains — or is starved by —
    // another connection's flows. The abort-on-drop guard keeps it from
    // outliving the pump.
    let drain = {
        let tracker = runtime.task_tracker().clone();
        let runtime = runtime.clone();
        let user = user.clone();
        let flow_prefix = format!("udp-face/{face_id}/");
        let moved = Arc::clone(&moved);
        AbortOnDrop(tracker.spawn(async move {
            loop {
                let responses = drain_udp_face_responses(
                    &runtime,
                    &user,
                    Some(&flow_prefix),
                    FACE_DRAIN_MAX_DATAGRAMS,
                    FACE_DRAIN_MAX_WAIT,
                )
                .await;
                moved.fetch_add(responses.len() as u64, Ordering::Relaxed);
                for response in responses {
                    responder
                        .respond(
                            response.source,
                            &response.source_endpoint,
                            &response.payload,
                        )
                        .await?;
                }
            }
        }))
    };

    // The send loop never awaits a target's response, so a slow flow cannot
    // hold up reading the connection's next datagram.
    let send_loop = async {
        loop {
            match receiver.next().await? {
                Some(datagram) => {
                    moved.fetch_add(1, Ordering::Relaxed);
                    let flow_id = format!("udp-face/{face_id}/{}", datagram.source);
                    let _ = send_udp_flow_datagram(
                        runtime,
                        UdpDatagram {
                            flow_id: Some(flow_id),
                            pump_queue: None,
                            // An authenticated datagram face (Trojan/Hysteria2
                            // UDP associate); the same label the stream
                            // dispatcher reports for these sessions.
                            inbound: "udp-associate",
                            user: user.clone(),
                            source: datagram.source,
                            target: datagram.target,
                            payload: datagram.payload,
                            process_name: None,
                            process_path: None,
                        },
                    )
                    .await;
                }
                None => return Ok::<(), String>(()),
            }
        }
    };
    tokio::pin!(send_loop);

    // Whichever side ends first ends the face: the receiver closing (a clean
    // end) or the drain returning (a responder error). The guard aborts the
    // drain as this scope unwinds.
    let mut drain = drain;
    let cancel = runtime.connection_cancellation();
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(InboundSessionError::Cancelled),
        () = face_idle(&moved) => Err(InboundSessionError::Datagrams(format!(
            "datagram face moved nothing for {RELAY_IDLE_TIMEOUT:?}"
        ))),
        result = &mut send_loop => result.map_err(InboundSessionError::Datagrams),
        result = &mut drain.0 => match result {
            Ok(Ok(())) => Err(InboundSessionError::Datagrams("datagram face responder ended".into())),
            Ok(Err(error)) => Err(InboundSessionError::Datagrams(error)),
            Err(error) => Err(InboundSessionError::Datagrams(format!("datagram face responder task failed: {error}"))),
        },
    }
}

async fn write_reply<S: AsyncWrite + Unpin + ?Sized>(
    io: &mut S,
    reply: &[u8],
) -> Result<(), TcpFlowFailure> {
    if reply.is_empty() {
        return Ok(());
    }
    io.write_all(reply)
        .await
        .map_err(|error| TcpFlowFailure::io(TcpFlowIoSide::Client, TcpFlowIoAction::Write, error))
}

fn flow_error(
    context: &TcpFlowContext,
    stage: TcpFlowStage,
    cause: TcpFlowFailure,
    session: Option<&SessionGuard>,
) -> NativeTcpFlowError {
    let mut error = NativeTcpFlowError::new(stage, context.clone(), cause);
    if let Some(session) = session {
        session.record_termination(ConnectionTermination::from_failure(stage, &error.cause));
        let counters = session.byte_counters();
        error.upload_bytes = counters.up.load(Ordering::Relaxed);
        error.download_bytes = counters.down.load(Ordering::Relaxed);
    }
    error
}

/// Unix time in seconds for a relay trace line, so a trace read beside other
/// records lines up with them whatever host wrote it.
fn trace_clock() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

/// Whether `EGRIO_RELAY_TRACE` per-flow stage tracing is on (any value but
/// `0`). Read once: the toggle is a process-start diagnostic decision, and the
/// hot path pays one atomic load instead of an env lookup per flow.
fn relay_trace_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("EGRIO_RELAY_TRACE").is_ok_and(|value| value != "0"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::capture::NativeCoreCaptureConfig;
    use crate::egress::{EgressRuntime, NativeCoreEgressConfig};
    use crate::outbound::{BoxedOutboundStream, OutboundConnector, OutboundFuture};
    use crate::profile::{RouteRule, RuleKind, RuntimeProfile};
    use crate::runtime::{NativeCoreSessionState, RuntimeSnapshot};

    #[derive(Debug)]
    struct DatagramOnlyConnector;

    impl OutboundConnector for DatagramOnlyConnector {
        fn connect_stream<'a>(
            &'a self,
            _egress: &'a EgressRuntime,
            _target: &'a ConnectTarget,
            _early_data: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(std::future::ready(Err(
                crate::outbound::OutboundError::new(
                    crate::outbound::OutboundStage::Config,
                    "TCP dial must not run for a datagram-only connector",
                ),
            )))
        }

        fn supports_tcp(&self) -> bool {
            false
        }
    }

    #[derive(Debug)]
    struct FailingDialConnector;

    impl OutboundConnector for FailingDialConnector {
        fn connect_stream<'a>(
            &'a self,
            _egress: &'a EgressRuntime,
            target: &'a ConnectTarget,
            _early_data: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            assert!(target.ip().is_none(), "a proxy is handed the name");
            Box::pin(std::future::ready(Err(
                crate::outbound::OutboundError::new(
                    crate::outbound::OutboundStage::HopConnect,
                    "TLS handshake failed: timed out after 8s",
                ),
            )))
        }
    }

    #[derive(Debug)]
    struct PendingDialConnector;
    impl OutboundConnector for PendingDialConnector {
        fn connect_stream<'a>(
            &'a self,
            _: &'a EgressRuntime,
            _: &'a ConnectTarget,
            _: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(std::future::pending())
        }
    }

    #[derive(Debug)]
    struct AnswerThenResetConnector;
    struct AnswerThenReset(bool);
    impl tokio::io::AsyncRead for AnswerThenReset {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.0 {
                self.0 = false;
                buffer.put_slice(b"pong");
                std::task::Poll::Ready(Ok(()))
            } else {
                std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
            }
        }
    }
    impl tokio::io::AsyncWrite for AnswerThenReset {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl OutboundConnector for AnswerThenResetConnector {
        fn connect_stream<'a>(
            &'a self,
            _: &'a EgressRuntime,
            target: &'a ConnectTarget,
            _: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            assert_eq!(target.host, "target.example");
            Box::pin(async { Ok(Box::new(AnswerThenReset(true)) as BoxedOutboundStream) })
        }
    }
    fn terminal_test_runtime(connector: Arc<dyn OutboundConnector>) -> NativeCoreRuntime {
        let mut profile = RuntimeProfile::new("terminal-facts");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "test-node",
            no_resolve: false,
        }]
        .into();
        let mut snapshot = RuntimeSnapshot::compile(
            &profile,
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        snapshot.insert_outbound_for_test("test-node", connector);
        NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default())
    }
    fn terminal_test_stream(io: tokio::io::DuplexStream) -> AcceptedStream {
        AcceptedStream {
            inbound: "test",
            user: None,
            process: ClientOwner::Known(None),
            target: ConnectTarget {
                host: "target.example".into(),
                port: 443,
            },
            io: Box::new(io),
            replies: Default::default(),
            reset: None,
        }
    }

    /// A node that takes what it is sent and never answers or closes.
    #[derive(Debug)]
    struct SilentConnector;
    struct Silent;
    impl tokio::io::AsyncRead for Silent {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }
    impl tokio::io::AsyncWrite for Silent {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    impl OutboundConnector for SilentConnector {
        fn connect_stream<'a>(
            &'a self,
            _: &'a EgressRuntime,
            _: &'a ConnectTarget,
            _: &'a [u8],
        ) -> OutboundFuture<'a, BoxedOutboundStream> {
            Box::pin(async { Ok(Box::new(Silent) as BoxedOutboundStream) })
        }
    }

    fn observed_reset(accepted: &mut AcceptedStream) -> Arc<std::sync::atomic::AtomicBool> {
        let reset = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&reset);
        accepted.reset = Some(Box::new(move || {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        reset
    }

    #[tokio::test]
    async fn a_relay_core_cancels_runs_the_inbound_reset() {
        let runtime = terminal_test_runtime(Arc::new(SilentConnector));
        let running = runtime.clone();
        let (_client, server) = tokio::io::duplex(128);
        let mut accepted = terminal_test_stream(server);
        let reset = observed_reset(&mut accepted);
        let task =
            tokio::spawn(async move { dispatch_accepted_stream(&running, None, accepted).await });
        tokio::time::timeout(Duration::from_secs(2), async {
            while !runtime
                .session_registry()
                .snapshot()
                .iter()
                .any(|s| s.phase == SessionPhase::Established)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!reset.load(std::sync::atomic::Ordering::SeqCst));
        // A network change ends the sessions its lost egress strands this way.
        runtime.session_registry().kill_all();
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(matches!(error.cause, TcpFlowFailure::Cancelled));
        assert!(reset.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dispatcher_preserves_real_upstream_failure_after_answered_bytes() {
        let runtime = terminal_test_runtime(Arc::new(AnswerThenResetConnector));
        let (_client, server) = tokio::io::duplex(128);
        let mut accepted = terminal_test_stream(server);
        let reset = observed_reset(&mut accepted);
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            dispatch_accepted_stream(&runtime, None, accepted),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.download_bytes, 4);
        // The upstream's own end reaches the client as a close.
        assert!(!reset.load(std::sync::atomic::Ordering::SeqCst));
        let finished = runtime.session_registry().finished_snapshot();
        assert!(matches!(
            finished[0].termination,
            ConnectionTermination::Failed {
                stage: TcpFlowStage::Relay,
                cause: crate::ConnectionFailureCause::Io {
                    side: TcpFlowIoSide::Upstream,
                    action: TcpFlowIoAction::Read,
                    ..
                },
            }
        ));
        assert_eq!(runtime.session_registry().terminal_counts(), (0, 1));
    }

    #[tokio::test]
    async fn dispatcher_distinguishes_control_cancellation_from_an_unreported_owner_abort() {
        for control_cancel in [false, true] {
            let runtime = terminal_test_runtime(Arc::new(PendingDialConnector));
            let running = runtime.clone();
            let (_client, server) = tokio::io::duplex(128);
            let task = tokio::spawn(async move {
                dispatch_accepted_stream(&running, None, terminal_test_stream(server)).await
            });
            tokio::time::timeout(Duration::from_secs(2), async {
                while !runtime
                    .session_registry()
                    .snapshot()
                    .iter()
                    .any(|s| s.phase == SessionPhase::Dialing)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            if control_cancel {
                runtime.session_registry().kill_all();
            } else {
                task.abort();
            }
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap();
            if control_cancel {
                assert!(matches!(
                    result.unwrap().unwrap_err().cause,
                    TcpFlowFailure::Cancelled
                ));
            } else {
                assert!(result.unwrap_err().is_cancelled());
            }
            let finished = runtime.session_registry().finished_snapshot();
            assert_eq!(
                finished[0].termination,
                if control_cancel {
                    ConnectionTermination::Cancelled
                } else {
                    ConnectionTermination::Unknown
                }
            );
            assert_eq!(runtime.session_registry().terminal_counts(), (0, 0));
        }
    }

    #[tokio::test]
    async fn aborting_a_pending_failure_reply_does_not_erase_the_dial_failure() {
        static FAILURE_REPLY: &[u8] = &[b'x'; 4096];
        let runtime = terminal_test_runtime(Arc::new(FailingDialConnector));
        let running = runtime.clone();
        let (mut client, server) = tokio::io::duplex(64);
        let mut accepted = terminal_test_stream(server);
        accepted.replies.dial_failed = FAILURE_REPLY;
        let task =
            tokio::spawn(async move { dispatch_accepted_stream(&running, None, accepted).await });
        let mut byte = [0];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(byte, [b'x']);
        assert!(!task.is_finished());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let finished = runtime.session_registry().finished_snapshot();
        assert!(matches!(&finished[0].termination,
            ConnectionTermination::Failed { stage: TcpFlowStage::Dial, cause: crate::ConnectionFailureCause::Outbound { stage: crate::OutboundStage::HopConnect, message } }
                if message.contains("timed out after 8s")));
        assert_eq!(runtime.session_registry().terminal_counts(), (0, 1));
    }

    #[tokio::test]
    async fn dial_failure_keeps_fake_ip_domain_rule_and_concrete_node_without_hiding_timeout() {
        let mut profile = RuntimeProfile::new("fake-ip-failure");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "Selection",
            no_resolve: false,
        }]
        .into();
        profile.groups.push(crate::PolicyGroup {
            id: "select".into(),
            name: "Selection".into(),
            kind: crate::PolicyGroupKind::Select,
            members: vec!["TW".into()],
            selected: Some("TW".into()),
            interval_seconds: None,
            test_url: None,
        });
        let mut snapshot = RuntimeSnapshot::compile(
            &profile,
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        snapshot.insert_outbound_for_test("TW", Arc::new(FailingDialConnector));
        let runtime =
            NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default());
        let ip = runtime.fake_dns().allocate_ipv4("image.example").unwrap();
        let (client, server) = tokio::io::duplex(128);
        // Even if the failure reply also fails, it must not erase the original
        // dial timeout or downgrade it to an expected client close.
        drop(client);
        let error = dispatch_accepted_stream(
            &runtime,
            None,
            AcceptedStream {
                inbound: "test",
                user: None,
                process: ClientOwner::Known(None),
                target: ConnectTarget {
                    host: ip.to_string(),
                    port: 443,
                },
                io: Box::new(server),
                replies: crate::inbound::acceptor::InboundReplyPlan {
                    dial_failed: b"failed",
                    ..Default::default()
                },
                reset: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.stage, TcpFlowStage::Dial);
        assert!(error.context.session_id.is_some());
        assert_eq!(error.context.target, format!("{ip}:443"));
        assert_eq!(error.context.route_host.as_deref(), Some("image.example"));
        assert_eq!(
            error.context.dial_target.as_deref(),
            Some("image.example:443")
        );
        assert_eq!(error.context.outbound.as_deref(), Some("Selection"));
        assert_eq!(error.context.resolved_outbound.as_deref(), Some("TW"));
        assert_eq!(
            error.context.matched_rule.as_deref(),
            Some("MATCH,Selection")
        );
        assert!(
            matches!(&error.cause, TcpFlowFailure::Outbound { stage: crate::OutboundStage::HopConnect, message } if message.contains("timed out after 8s")),
            "{error}"
        );
        assert!(!error.is_expected_close());
        assert_eq!((error.upload_bytes, error.download_bytes), (0, 0));
        let finished = runtime.session_registry().finished_snapshot();
        assert_eq!(finished.len(), 1);
        assert!(matches!(&finished[0].termination,
            ConnectionTermination::Failed { stage: TcpFlowStage::Dial, cause: crate::ConnectionFailureCause::Outbound { stage: crate::OutboundStage::HopConnect, message } }
                if message.contains("timed out after 8s")));
    }

    #[tokio::test]
    async fn a_rejected_session_records_its_route_and_runs_the_inbound_reset() {
        let mut profile = RuntimeProfile::new("reject-reset");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "REJECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::pinned(
            Arc::new(RuntimeSnapshot::compile(
                &profile,
                NativeCoreEgressConfig::default(),
                NativeCoreCaptureConfig::default(),
                None,
                crate::policy_group::GroupStateTable::default(),
            )),
            NativeCoreSessionState::default(),
        );
        let (mut client, server) = tokio::io::duplex(128);
        let reset = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&reset);
        let accepted = AcceptedStream {
            inbound: "test",
            user: None,
            process: ClientOwner::Known(Some(Arc::new(crate::attribution::ProcessInfo {
                name: Some("curl.exe".into()),
                path: None,
            }))),
            target: ConnectTarget {
                host: "example.com".into(),
                port: 443,
            },
            io: Box::new(server),
            replies: Default::default(),
            reset: Some(Box::new(move || {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
            })),
        };

        let outcome = dispatch_accepted_stream(&runtime, None, accepted)
            .await
            .expect("a REJECT route is an outcome");
        assert_eq!(outcome.outbound, "REJECT");
        assert!(reset.load(std::sync::atomic::Ordering::SeqCst));
        let finished = runtime.session_registry().finished_snapshot();
        assert_eq!(finished.len(), 1);
        let row = &finished[0].snapshot;
        assert_eq!(row.outbound.as_deref(), Some("REJECT"));
        assert_eq!(row.matched_rule.as_deref(), Some("MATCH,REJECT"));
        assert_eq!(row.process_name.as_deref(), Some("curl.exe"));
        assert_eq!(
            finished[0].termination,
            crate::ConnectionTermination::RouteRejected
        );
        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("stream ends");
        assert!(received.is_empty(), "a reset inbound writes no reply");
    }

    /// The selector most converted subscriptions carry for ad blocking,
    /// `REJECT` or `DIRECT`: while it chooses `REJECT` its flows are
    /// rejected routes, not dials of an outbound that does not exist.
    #[tokio::test]
    async fn a_group_that_chooses_reject_rejects_its_flows() {
        use crate::profile::{PolicyGroup, PolicyGroupKind};
        let group = |name: &str, members: &[&str]| PolicyGroup {
            id: name.into(),
            name: name.into(),
            kind: PolicyGroupKind::Select,
            members: members.iter().map(|member| (*member).to_string()).collect(),
            interval_seconds: None,
            test_url: None,
            selected: None,
        };
        let mut profile = RuntimeProfile::new("group-reject");
        profile.groups = vec![
            group("Ads", &["REJECT", "DIRECT"]),
            group("Outer", &["Ads", "DIRECT"]),
            group("Plain", &["DIRECT"]),
        ];
        profile.rules = vec![
            RouteRule {
                kind: RuleKind::DomainSuffix,
                payload: Some("ads.test"),
                outbound: "Ads",
                no_resolve: false,
            },
            RouteRule {
                kind: RuleKind::DomainSuffix,
                payload: Some("nested.test"),
                outbound: "Outer",
                no_resolve: false,
            },
            RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: "Plain",
                no_resolve: false,
            },
        ]
        .into();
        let sessions = NativeCoreSessionState::default();
        let runtime = NativeCoreRuntime::pinned(
            Arc::new(RuntimeSnapshot::compile(
                &profile,
                NativeCoreEgressConfig::default(),
                NativeCoreCaptureConfig::default(),
                None,
                sessions.group_state.clone(),
            )),
            sessions,
        );
        let routed = |host: &str| {
            runtime
                .route(&crate::RouteMatchInput {
                    host: Some(host.into()),
                    destination_port: Some(443),
                    ..Default::default()
                })
                .outbound
        };
        assert_eq!(routed("x.ads.test"), "REJECT");
        assert_eq!(routed("x.nested.test"), "REJECT", "through a nested group");
        assert_eq!(routed("other.test"), "Plain", "a group that cannot reject");

        let (mut client, server) = tokio::io::duplex(128);
        let mut accepted = terminal_test_stream(server);
        accepted.target = ConnectTarget {
            host: "x.ads.test".into(),
            port: 443,
        };
        let reset = observed_reset(&mut accepted);
        let outcome = dispatch_accepted_stream(&runtime, None, accepted)
            .await
            .expect("a rejected route is an outcome");
        assert_eq!(outcome.outbound, "REJECT");
        assert!(reset.load(std::sync::atomic::Ordering::SeqCst));
        let finished = runtime.session_registry().finished_snapshot();
        assert_eq!(
            finished[0].termination,
            crate::ConnectionTermination::RouteRejected
        );
        assert_eq!(finished[0].snapshot.outbound.as_deref(), Some("REJECT"));
        assert_eq!(
            finished[0].snapshot.matched_rule.as_deref(),
            Some("DOMAIN-SUFFIX,ads.test,Ads")
        );
        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("stream ends");

        // The user's other choice routes the same names through the group.
        runtime.group_state().select("Ads", "DIRECT");
        assert_eq!(routed("x.ads.test"), "Ads");
        assert_eq!(routed("x.nested.test"), "Outer");
        let target = ConnectTarget {
            host: "x.ads.test".into(),
            port: 443,
        };
        assert_eq!(
            runtime
                .resolve_outbound("Ads", &target)
                .map(|resolved| resolved.name),
            Some("DIRECT".into())
        );
    }

    #[tokio::test]
    async fn a_failed_dial_runs_the_inbound_reset() {
        let mut profile = RuntimeProfile::new("dial-reset");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "TW",
            no_resolve: false,
        }]
        .into();
        let mut snapshot = RuntimeSnapshot::compile(
            &profile,
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        snapshot.insert_outbound_for_test("TW", Arc::new(FailingDialConnector));
        let runtime =
            NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default());
        let (mut client, server) = tokio::io::duplex(128);
        let reset = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = Arc::clone(&reset);
        let error = dispatch_accepted_stream(
            &runtime,
            None,
            AcceptedStream {
                inbound: "test",
                user: None,
                process: ClientOwner::Known(None),
                target: ConnectTarget {
                    host: "example.com".into(),
                    port: 443,
                },
                io: Box::new(server),
                replies: Default::default(),
                reset: Some(Box::new(move || {
                    observed.store(true, std::sync::atomic::Ordering::SeqCst);
                })),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.stage, TcpFlowStage::Dial);
        assert!(reset.load(std::sync::atomic::Ordering::SeqCst));
        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("stream ends");
        assert!(received.is_empty(), "a reset inbound writes no reply");
    }

    #[tokio::test]
    async fn tcp_unsupported_outbound_writes_unavailable_reply_without_dialing() {
        let mut profile = RuntimeProfile::new("tcp-unsupported");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "datagram-only",
            no_resolve: false,
        }]
        .into();
        let mut snapshot = RuntimeSnapshot::compile(
            &profile,
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        snapshot.insert_outbound_for_test("datagram-only", Arc::new(DatagramOnlyConnector));
        let runtime =
            NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default());
        let (mut client, server) = tokio::io::duplex(128);
        let reply = b"outbound unavailable";
        let accepted = AcceptedStream {
            inbound: "test",
            user: None,
            process: ClientOwner::Known(None),
            target: ConnectTarget {
                host: "example.com".into(),
                port: 443,
            },
            io: Box::new(server),
            replies: crate::inbound::acceptor::InboundReplyPlan {
                outbound_unavailable: reply,
                ..Default::default()
            },
            reset: None,
        };

        let error = dispatch_accepted_stream(&runtime, None, accepted)
            .await
            .expect_err("datagram-only outbound must reject TCP");
        assert!(
            matches!(&error.cause, TcpFlowFailure::Message(message) if message.contains("does not support TCP flows")),
            "{error}"
        );
        assert_eq!(error.stage, TcpFlowStage::Route);

        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("read unavailable reply");
        assert_eq!(received, reply);
    }
    /// A face whose client stopped moving datagrams ends with its budget;
    /// neither half of the face can tell on its own.
    #[tokio::test(start_paused = true)]
    async fn a_face_that_moves_nothing_runs_out_of_its_budget() {
        let moved = AtomicU64::new(0);
        tokio::time::timeout(RELAY_IDLE_TIMEOUT * 2, face_idle(&moved))
            .await
            .expect("the budget ends a face that moved nothing");
    }

    /// The budget follows activity, not the face's age, so an associate that
    /// keeps moving datagrams outlives any number of budgets.
    #[tokio::test(start_paused = true)]
    async fn a_face_that_keeps_moving_datagrams_outlives_its_budget() {
        let moved = AtomicU64::new(0);
        let budget = face_idle(&moved);
        tokio::pin!(budget);
        for _ in 0..4 {
            tokio::select! {
                () = &mut budget => panic!("the budget ended a face that kept moving"),
                () = tokio::time::sleep(RELAY_IDLE_TIMEOUT - Duration::from_secs(1)) => {}
            }
            moved.fetch_add(1, Ordering::Relaxed);
        }
    }
}
