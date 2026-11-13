//! File-descriptor headroom for data-path processes.
//!
//! The core's bounded session tables still imply real descriptor counts: the
//! UDP session table alone may hold up to 1024 sockets, plus TCP relays,
//! listeners, and IPC connections. macOS defaults the per-process soft
//! `RLIMIT_NOFILE` to 256 (SSH sessions and launchd GUI apps alike), so a
//! loaded capture session would exhaust descriptors long before any table
//! cap is reached. Every long-running host entrypoint raises the soft limit
//! toward the hard limit at startup.
//!
//! This lives in the daemon, not `egrio-core`: `setrlimit` mutates
//! process-level OS state, and the core crate owns only the proxy data
//! plane. Hosts that embed the core without this facade set their own
//! descriptor headroom.

/// Raises the soft fd limit toward the hard limit, bounded at 8192 (well
/// past every table cap combined, and under macOS's `OPEN_MAX`). Returns
/// the soft limit in effect afterwards. Best-effort: failures leave the
/// previous limit in place, which only means earlier `Too many open files`
/// under load.
#[cfg(unix)]
pub fn raise_fd_soft_limit() -> u64 {
    const TARGET: libc::rlim_t = 8192;

    // SAFETY: getrlimit/setrlimit with a properly initialized rlimit out
    // parameter; no memory is shared beyond the struct.
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            return 0;
        }
        let desired = TARGET.min(limit.rlim_max);
        if limit.rlim_cur >= desired {
            return limit.rlim_cur;
        }
        let previous = limit.rlim_cur;
        limit.rlim_cur = desired;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            return previous;
        }
        desired
    }
}

/// Windows has no `RLIMIT_NOFILE` analogue that constrains sockets this
/// way; the call is a no-op there so hosts can call it unconditionally.
#[cfg(not(unix))]
pub fn raise_fd_soft_limit() -> u64 {
    0
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn soft_limit_covers_the_session_table_caps() {
        let limit = raise_fd_soft_limit();
        // 1024 UDP session sockets + listeners/IPC/TCP headroom.
        assert!(
            limit >= 2048,
            "soft fd limit {limit} leaves the UDP session table cap unusable"
        );
    }
}
