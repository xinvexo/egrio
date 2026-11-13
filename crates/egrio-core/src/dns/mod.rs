mod answers;
pub(crate) mod cache;
pub mod config;
mod connections;
pub(crate) mod fake_ip;
pub(crate) mod fake_ip_file;
pub(crate) mod hosts;
pub(crate) mod pattern;
pub mod policy;
pub(crate) mod resolver;
pub(crate) mod service;
pub(crate) mod transport;
pub(crate) mod wire;

pub use policy::{DnsDecision, DnsDecisionAction, DnsEngine, DnsQueryInput, DnsRecordType};
