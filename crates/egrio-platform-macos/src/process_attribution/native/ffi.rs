use std::ffi::c_void;

pub(super) const MAX_CANDIDATES: usize = 2048;
pub(super) const LIMIT_PIDS: u32 = 1;
pub(super) const LIMIT_FDS: u32 = 2;
pub(super) const LIMIT_CANDIDATES: u32 = 4;
pub(super) const TIMED_OUT: u32 = 8;
pub(super) const CANCELLED: u32 = 16;
#[cfg(test)]
pub(super) const SYSCALL_ERROR: u32 = 128;
pub(super) const REUSE_PORT: u32 = 1;
pub(super) const REUSE_ADDR: u32 = 2;
pub(super) const SHARED: u32 = 4;
pub(super) const DUAL_STACK: u32 = 8;
pub(super) const USERLAND_FLOW: u32 = 16;

#[repr(C)]
pub(super) struct RawQuery {
    pub protocol: u32,
    pub local_port: u16,
    pub reserved: u16,
}
#[repr(C)]
pub(super) struct RawEndpoint {
    pub address: [u8; 16],
    pub family: u32,
    pub scope_id: u32,
    pub port: u16,
    pub reserved: u16,
}
#[repr(C)]
pub(super) struct RawCandidate {
    pub start_sec: u64,
    pub start_usec: u64,
    pub socket_id: u64,
    pub socket_generation: u64,
    pub pid: u32,
    pub fd: u32,
    pub protocol: u32,
    pub flags: u32,
    pub tcp_state: u32,
    pub owner_pid: u32,
    pub local: RawEndpoint,
    pub remote: RawEndpoint,
    pub executable: [u8; 4096],
}
#[repr(C)]
#[derive(Default)]
pub(super) struct RawReport {
    pub elapsed_ns: u64,
    pub flags: u32,
    pub pids_scanned: u32,
    pub fds_scanned: u32,
    pub permission_denied: u32,
    pub raced: u32,
    pub candidate_count: u32,
    pub syscall_errors: u32,
    pub userland_flows: u32,
}
#[cfg(test)]
#[repr(C)]
pub(super) struct RawUserlandFlow {
    pub protocol: u32,
    pub owner_pid: u32,
    pub effective_pid: u32,
    pub local: RawEndpoint,
    pub remote: RawEndpoint,
}
pub(super) type CancelCallback = Option<unsafe extern "C" fn(*mut c_void) -> i32>;
/// Both ownership sources share one bridge signature and report shape.
pub(super) type ScanEntry = unsafe extern "C" fn(
    queries: *const RawQuery,
    count: u32,
    budget_ns: u64,
    candidates: *mut RawCandidate,
    capacity: u32,
    report: *mut RawReport,
    cancelled: CancelCallback,
    context: *mut c_void,
) -> i32;
unsafe extern "C" {
    pub(super) fn egrio_macos_flow_candidate_size() -> usize;
    pub(super) fn egrio_macos_scan_sockets(
        queries: *const RawQuery,
        count: u32,
        budget_ns: u64,
        candidates: *mut RawCandidate,
        capacity: u32,
        report: *mut RawReport,
        cancelled: CancelCallback,
        context: *mut c_void,
    ) -> i32;
    pub(super) fn egrio_macos_scan_userland_flows(
        queries: *const RawQuery,
        count: u32,
        budget_ns: u64,
        candidates: *mut RawCandidate,
        capacity: u32,
        report: *mut RawReport,
        cancelled: CancelCallback,
        context: *mut c_void,
    ) -> i32;
    #[cfg(test)]
    pub(super) fn egrio_parse_userland_snapshot(
        bytes: *const u8,
        length: usize,
        protocol: u32,
        queries: *const RawQuery,
        query_count: u32,
        rows: *mut RawUserlandFlow,
        capacity: u32,
        count: *mut u32,
        report: *mut RawReport,
        deadline: u64,
        cancelled: CancelCallback,
        context: *mut c_void,
    ) -> i32;
}
