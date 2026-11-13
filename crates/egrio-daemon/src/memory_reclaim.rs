//! Gives back to the system the memory glibc keeps after a burst of traffic.
//! glibc holds freed chunks in its arenas and returns pages only from the top
//! of the main heap; after 64 parallel transfers through the Linux TUN the
//! process stayed at 46–81 MB resident, and `malloc_trim(0)` brought it back
//! to about 15 MB (malloc_trim(3): since glibc 2.8 it also frees the unused
//! pages inside the arenas). Once a minute a thread trims; with little free
//! that is a walk over the arenas' bins.
//!
//! This lives in the daemon, not `egrio-core`, for the reason `fd_limit`
//! does: the allocator is process-level state, and the core crate owns only
//! the proxy data plane. Long-running host entrypoints start it; hosts that
//! embed the core without this facade manage their own allocator.

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Starts the trimming thread once per process on Linux with glibc; a no-op
/// elsewhere, where the allocator returns memory on its own.
pub fn start_memory_reclaim() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        static STARTED: std::sync::Once = std::sync::Once::new();
        STARTED.call_once(|| {
            // Without the thread memory is only kept longer.
            let _ = std::thread::Builder::new()
                .name("egrio-malloc-trim".into())
                .spawn(|| loop {
                    std::thread::sleep(INTERVAL);
                    // SAFETY: malloc_trim only releases memory malloc holds
                    // free.
                    unsafe { libc::malloc_trim(0) };
                });
        });
    }
}
