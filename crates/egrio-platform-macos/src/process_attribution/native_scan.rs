use super::ffi::*;
use super::*;
use std::ffi::{c_void, OsString};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::os::unix::ffi::OsStringExt;
use std::sync::atomic::Ordering;
use std::time::Instant;

thread_local! {
    static ROWS: std::cell::RefCell<Vec<MaybeUninit<RawCandidate>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

unsafe extern "C" fn is_cancelled(context: *mut c_void) -> i32 {
    // C treats this as an opaque pointer and calls back only during scan().
    i32::from(unsafe { &*context.cast::<AtomicBool>() }.load(Ordering::Acquire))
}
pub(super) fn scan(
    source: Source,
    requests: &[FlowKey],
    budget: Duration,
    cancelled: &AtomicBool,
) -> ScanReport {
    let started = Instant::now();
    if requests.len() > egrio_core::FLOW_SCAN_BATCH
        || requests.iter().any(|flow| flow.source_port == 0)
    {
        return ScanReport {
            limited: true,
            ..Default::default()
        };
    }
    if requests.is_empty() {
        return ScanReport {
            complete: true,
            ..Default::default()
        };
    }
    if cancelled.load(Ordering::Acquire) {
        return ScanReport {
            cancelled: true,
            ..Default::default()
        };
    }
    // Sorted and distinct: the shim matches each socket by binary search.
    let mut queries = requests
        .iter()
        .map(|flow| RawQuery {
            protocol: match flow.protocol {
                FlowProtocol::Tcp => 6,
                FlowProtocol::Udp => 17,
            },
            local_port: flow.source_port,
            reserved: 0,
        })
        .collect::<Vec<_>>();
    queries.sort_unstable_by_key(|query| (query.protocol, query.local_port));
    queries.dedup_by_key(|query| (query.protocol, query.local_port));
    if unsafe { egrio_macos_flow_candidate_size() } != std::mem::size_of::<RawCandidate>() {
        return ScanReport {
            syscall_errors: 1,
            ..Default::default()
        };
    }
    // The rows hold MAX_CANDIDATES candidates of over 4 KiB each; the one
    // worker thread that scans keeps them between scans.
    let mut rows = ROWS.with_borrow_mut(std::mem::take);
    if rows.len() != MAX_CANDIDATES {
        rows = Vec::with_capacity(MAX_CANDIDATES);
        // MaybeUninit has no initialization invariant; the shim fully
        // initializes exactly candidate_count rows and never reads the unused
        // output capacity.
        unsafe {
            rows.set_len(MAX_CANDIDATES);
        }
    }
    let mut raw = RawReport::default();
    let budget_ns = budget.min(Duration::from_millis(100)).as_nanos() as u64;
    let entry: ScanEntry = match source {
        Source::Sockets => egrio_macos_scan_sockets,
        Source::UserlandFlows => egrio_macos_scan_userland_flows,
    };
    let result = unsafe {
        entry(
            queries.as_ptr(),
            queries.len() as u32,
            budget_ns,
            rows.as_mut_ptr().cast(),
            MAX_CANDIDATES as u32,
            &mut raw,
            Some(is_cancelled),
            (cancelled as *const AtomicBool).cast_mut().cast(),
        )
    };
    let mut report = ScanReport {
        complete: result == 0 && raw.flags == 0,
        elapsed: started.elapsed(),
        pids_scanned: raw.pids_scanned,
        fds_scanned: raw.fds_scanned,
        userland_flows: raw.userland_flows,
        permission_denied: raw.permission_denied,
        raced: raw.raced,
        syscall_errors: raw.syscall_errors,
        limited: raw.flags & (LIMIT_PIDS | LIMIT_FDS | LIMIT_CANDIDATES) != 0,
        timed_out: raw.flags & TIMED_OUT != 0,
        cancelled: raw.flags & CANCELLED != 0,
        unsupported: false,
        candidates: Vec::new(),
    };
    if raw.candidate_count as usize > rows.len() {
        report.complete = false;
        report.syscall_errors += 1;
    } else {
        for row in rows.iter().take(raw.candidate_count as usize) {
            let row = unsafe { row.assume_init_ref() };
            match decode(source, row) {
                Some(candidate) => report.candidates.push(candidate),
                None => {
                    report.complete = false;
                    report.raced += 1;
                }
            }
        }
    }
    ROWS.with_borrow_mut(|kept| *kept = rows);
    report.elapsed = started.elapsed();
    report
}
fn endpoint(raw: &RawEndpoint) -> Option<SocketAddr> {
    match raw.family {
        4 => Some(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&raw.address[..4]).ok()?)),
            raw.port,
        )),
        6 => {
            let address = Ipv6Addr::from(raw.address);
            let scope = if address.is_unicast_link_local() || address.is_multicast() {
                raw.scope_id
            } else {
                0
            };
            Some(SocketAddr::V6(SocketAddrV6::new(
                address, raw.port, 0, scope,
            )))
        }
        _ => None,
    }
}
fn decode(source: Source, raw: &RawCandidate) -> Option<FlowCandidate> {
    let userland = raw.flags & USERLAND_FLOW != 0;
    if userland != (source == Source::UserlandFlows)
        || raw.pid == 0
        || raw.owner_pid == 0
        || raw.fd > i32::MAX as u32
        || (!userland && raw.socket_id == 0)
        || (userland && (raw.socket_id != 0 || raw.socket_generation != 0 || raw.fd != 0))
        || raw.start_usec >= 1_000_000
    {
        return None;
    }
    let protocol = match raw.protocol {
        6 => FlowProtocol::Tcp,
        17 => FlowProtocol::Udp,
        _ => return None,
    };
    let mut local_endpoint = endpoint(&raw.local)?;
    let mut remote_endpoint = if raw.remote.port == 0 {
        None
    } else {
        Some(endpoint(&raw.remote)?)
    };
    // Convert IPv4-mapped pairs together. A single mapped endpoint never
    // manufactures a cross-family tuple that the kernel did not report.
    if let SocketAddr::V6(local) = local_endpoint {
        if let Some(local_ip) = local.ip().to_ipv4_mapped() {
            let remote_ip = match remote_endpoint {
                Some(SocketAddr::V6(remote)) => remote
                    .ip()
                    .to_ipv4_mapped()
                    .map(|ip| SocketAddr::new(IpAddr::V4(ip), remote.port())),
                None => None,
                _ => return None,
            };
            if remote_endpoint.is_none() || remote_ip.is_some() {
                local_endpoint = SocketAddr::new(IpAddr::V4(local_ip), local.port());
                remote_endpoint = remote_ip;
            }
        }
    }
    let nul = raw.executable.iter().position(|byte| *byte == 0)?;
    if nul == 0 {
        return None;
    }
    let executable = PathBuf::from(OsString::from_vec(raw.executable[..nul].to_vec()));
    let dual_stack = raw.flags & DUAL_STACK != 0
        && local_endpoint.is_ipv6()
        && local_endpoint.ip().is_unspecified()
        && remote_endpoint.is_none();
    Some(FlowCandidate {
        pid: raw.pid,
        owner_pid: raw.owner_pid,
        userland,
        start_sec: raw.start_sec,
        start_usec: raw.start_usec,
        fd: raw.fd,
        socket_id: raw.socket_id,
        socket_generation: raw.socket_generation,
        protocol,
        local_endpoint,
        remote_endpoint,
        executable,
        reuse_port: raw.flags & REUSE_PORT != 0,
        reuse_addr: raw.flags & REUSE_ADDR != 0,
        shared: raw.flags & SHARED != 0,
        dual_stack,
    })
}
