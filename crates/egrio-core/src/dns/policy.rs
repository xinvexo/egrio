//! Read-only projection of the same DNS service plan used by real requests.
use super::service::DnsService;
use crate::profile::RuntimeProfile;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryInput {
    #[serde(default = "internet_class")]
    pub query_class: u16,
    pub domain: String,
    pub record_type: DnsRecordType,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
}
fn internet_class() -> u16 {
    1
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    Aaaa,
    Https,
    Svcb,
    Srv,
    Txt,
    Other,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DnsDecisionAction {
    Resolve,
    FakeIp,
    Block,
    Empty,
    /// A localhost name: the loopback address, never an upstream query.
    Loopback,
    /// A name the hosts map: their addresses, never an upstream query.
    Hosts,
}
#[derive(Debug, Clone, Serialize)]
pub struct DnsUpstreamDecision {
    pub transport: String,
    pub endpoint: String,
    pub outbound: Option<String>,
    pub requires_resolution: bool,
}
/// How a query would be answered, for a reader that is not going to run
/// it: the action, and for a query that goes upstream each source in the
/// order it is tried. A query that is run carries its plan, not this.
#[derive(Debug, Clone, Serialize)]
pub struct DnsDecision {
    pub action: DnsDecisionAction,
    pub upstreams: Vec<DnsUpstreamDecision>,
}
#[derive(Debug, Clone)]
pub struct DnsEngine {
    service: Arc<DnsService>,
}
impl DnsEngine {
    pub fn compile(profile: &RuntimeProfile, egress: crate::NativeCoreEgressConfig) -> Self {
        let runtime = crate::runtime::NativeCoreRuntime::compile_with_egress(profile, egress);
        Self {
            service: runtime.dns_service().clone(),
        }
    }
    pub fn evaluate(&self, input: &DnsQueryInput) -> DnsDecision {
        self.service.evaluate(input)
    }
}
