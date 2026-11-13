//! macOS flow-ownership snapshot boundary. Two independent sources answer the
//! same queries: libproc socket descriptors and the nstat userland flows that
//! the kernel exports with its PCB snapshot. SDK structures and the private PCB
//! wire decoder stay in C; Rust receives only owned bridge records. Sources
//! are recorded beside native/{socket_scan,userland_flow_scan}.c.
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use egrio_core::{FlowKey, FlowProtocol};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Source {
    /// BSD socket descriptors of same-UID processes.
    Sockets,
    /// Network.framework userland flows without a BSD descriptor.
    UserlandFlows,
}

/// One observed owner of a flow tuple.
#[derive(Clone, Debug)]
pub(crate) struct FlowCandidate {
    /// The process to publish: the descriptor holder, or the delegate that the
    /// kernel recorded for a userland flow.
    pub pid: u32,
    /// The process that holds the descriptor or userland flow.
    pub owner_pid: u32,
    pub userland: bool,
    pub start_sec: u64,
    pub start_usec: u64,
    #[cfg_attr(not(test), allow(dead_code))] // Native descriptor recheck diagnostics.
    pub fd: u32,
    pub socket_id: u64,
    pub socket_generation: u64,
    pub protocol: FlowProtocol,
    pub local_endpoint: SocketAddr,
    pub remote_endpoint: Option<SocketAddr>,
    pub executable: PathBuf,
    pub reuse_port: bool,
    pub reuse_addr: bool,
    pub shared: bool,
    /// An unconnected wildcard IPv6 socket with both INI family flags.
    pub dual_stack: bool,
}

/// One source's bounded observation. Its candidates may be used only when it
/// is complete.
#[derive(Clone, Debug, Default)]
pub(crate) struct ScanReport {
    pub candidates: Vec<FlowCandidate>,
    /// Complete only within the current effective-UID scope, never all users.
    pub complete: bool,
    pub elapsed: Duration,
    pub pids_scanned: u32,
    pub fds_scanned: u32,
    pub userland_flows: u32,
    pub permission_denied: u32,
    pub raced: u32,
    pub syscall_errors: u32,
    pub limited: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    pub unsupported: bool,
}

#[cfg(target_os = "macos")]
mod ffi;
#[cfg(target_os = "macos")]
#[path = "native_scan.rs"]
mod implementation;

pub(super) fn scan(
    source: Source,
    requests: &[FlowKey],
    budget: Duration,
    cancelled: &AtomicBool,
) -> ScanReport {
    #[cfg(target_os = "macos")]
    {
        implementation::scan(source, requests, budget, cancelled)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (source, requests, budget, cancelled);
        ScanReport {
            unsupported: true,
            ..Default::default()
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
#[path = "native_tests.rs"]
mod tests;

#[cfg(all(test, target_os = "macos"))]
#[path = "snapshot_tests.rs"]
mod snapshot_tests;
