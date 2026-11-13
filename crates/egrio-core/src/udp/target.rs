//! Core owns business-target DNS before a datagram reaches a protocol codec.
//! A live real-address association remains endpoint-independent; each new
//! domain-addressed datagram observes the shared DNS cache and its actual TTL.
//! In strict global mode a name resolves only past the proxy: the configured
//! servers answer through it, or, with only the local resolver configured,
//! the proxy resolves the name itself, as it does for a proxied TCP
//! connection.

use std::sync::{Arc, Mutex, Weak};

use crate::dns::service::{DnsService, QueryContext, QueryPurpose};
use crate::egress::EgressRuntime;
use crate::outbound::{OutboundError, OutboundStage};
use crate::runtime::NativeCoreRuntime;
use crate::target::ConnectTarget;
use tokio_util::sync::CancellationToken;

pub(super) struct TargetResolver {
    dns: Weak<DnsService>,
    egress: EgressRuntime,
    cancel: CancellationToken,
    direct: bool,
    /// Strict global mode: no business name resolves short of the proxy.
    strict: bool,
    context: QueryContext,
    /// The connector and first queued send must use the same resolution.
    /// This is consumed once, never a second per-association DNS cache.
    first: Mutex<Option<(ConnectTarget, ConnectTarget)>>,
}

impl TargetResolver {
    pub(super) fn new(runtime: NativeCoreRuntime, direct: bool, outbound: &str) -> Self {
        Self {
            strict: !direct && runtime.dns_service().strict_global(),
            dns: Arc::downgrade(runtime.dns_service()),
            egress: runtime.egress().clone(),
            // The egress policy's, not the route epoch's: a session that
            // keeps its route across a policy change keeps resolving, while
            // a change of the egress policy (the IPv6 switch) stops every
            // resolution it would have sent out the old one. A session the
            // change ends has its actor aborted with its socket, which drops
            // whatever it was resolving.
            cancel: runtime.egress().policy_cancel(),
            direct,
            context: QueryContext::for_business_outbound(outbound),
            first: Mutex::default(),
        }
    }

    /// Whether `host` goes to the proxy unresolved: strict global mode with
    /// no server but the local resolver to ask for it. A name the hosts map
    /// has its mapped address instead.
    ///
    /// Asked twice, seconds apart, and the two answers have to agree: the
    /// admission chooses the identity's transport on the first -- a name
    /// that passes gets a transport of its own, a name that resolves joins
    /// the one its outbound's identities share, which carries addresses only
    /// -- and the second decides what actually goes on the wire. They do
    /// agree, because for a live DNS generation this is a function of the
    /// host and the configuration alone: `strict` is read once, at
    /// construction; the hosts map is built once from the configuration; and
    /// the sources a name's policy names come from that same immutable
    /// configuration. A generation retired in between makes this `false` --
    /// the weak reference is gone -- and the resolve that follows fails on
    /// the same retired reference, so the name ends its preparation instead
    /// of riding a transport that carries addresses.
    pub(super) fn passes_name(&self, host: &str) -> bool {
        self.strict
            && self
                .dns
                .upgrade()
                .is_some_and(|dns| dns.hosts(host).is_none() && dns.only_system_answers(host))
    }

    pub(super) async fn prepare(
        &self,
        target: &ConnectTarget,
        reuse_for_first_send: bool,
    ) -> Result<ConnectTarget, OutboundError> {
        let resolved = self.resolve_current(target).await?;
        if reuse_for_first_send && target.ip().is_none() {
            *self.first.lock().expect("UDP initial target") =
                Some((target.clone(), resolved.clone()));
        }
        Ok(resolved)
    }

    pub(super) async fn resolve(&self, target: &ConnectTarget) -> Result<ConnectTarget, String> {
        if self.cancel.is_cancelled() {
            return Err("UDP target resolution cancelled by policy change".into());
        }
        let first = self.first.lock().expect("UDP initial target").take();
        if let Some((original, resolved)) = first {
            if &original == target {
                return Ok(resolved);
            }
        }
        self.resolve_current(target)
            .await
            .map_err(|error| error.message)
    }

    async fn resolve_current(
        &self,
        target: &ConnectTarget,
    ) -> Result<ConnectTarget, OutboundError> {
        let local = |message: String| OutboundError::new(OutboundStage::Local, message);
        if self.cancel.is_cancelled() {
            return Err(local(
                "UDP target resolution cancelled by policy change".into(),
            ));
        }
        if target.ip().is_some() {
            // A literal destination does not acquire DNS policy or resolver
            // lifetime. The IPv6 DNS switch does not forbid an existing
            // numeric destination, whether DIRECT or carried by a proxy.
            self.egress
                .validate_outbound_target(target, self.direct)
                .map_err(|reason| local(reason.to_string()))?;
            return Ok(target.clone());
        }
        if self.passes_name(&target.host) {
            return Ok(target.clone());
        }
        let dns = self
            .dns
            .upgrade()
            .ok_or_else(|| local("DNS service generation retired".into()))?;
        let purpose = if self.direct {
            QueryPurpose::DirectTarget
        } else {
            QueryPurpose::Application
        };
        let resolved = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(local("DNS resolution cancelled by policy change".into())),
            result = dns.resolve_target(target, purpose, self.context.clone()) => result
                .map_err(|error| OutboundError::new(OutboundStage::TargetResolve, error))?,
        };
        self.egress
            .validate_outbound_target(&resolved, self.direct)
            .map_err(|reason| local(reason.to_string()))?;
        Ok(resolved)
    }
}
