//! Descriptor headroom for the load harnesses and the device tests' session
//! churn. The production helper lives in `egrio-daemon` (`setrlimit` is
//! process-level OS state, outside the core crate's boundary), but these
//! hold hundreds of sockets at once, so they raise the soft limit themselves
//! like any other host.

/// Raises the soft fd limit toward the hard limit, bounded at 8192.
/// Best-effort: failures leave the previous limit in place.
#[cfg(unix)]
pub fn raise_fd_soft_limit() {
    const TARGET: libc::rlim_t = 8192;

    // SAFETY: getrlimit/setrlimit with a properly initialized rlimit out
    // parameter; no memory is shared beyond the struct.
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return;
        }
        let desired = TARGET.min(limit.rlim_max);
        if limit.rlim_cur >= desired {
            return;
        }
        limit.rlim_cur = desired;
        libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
    }
}

#[cfg(not(unix))]
pub fn raise_fd_soft_limit() {}
