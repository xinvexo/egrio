//! What the operating system charges the instrument's process for memory,
//! beside the heap the counting allocator sees: the difference between the
//! two is what the allocator holds on to and what is not heap at all.

// Each instrument includes this module and reads the part it reports.
#![allow(dead_code)]

#[derive(Clone, Copy, Default)]
pub struct OsMemory {
    /// Pages of the process in physical memory, shared ones included.
    pub resident: usize,
    /// Memory charged to the process alone: the commit charge on Windows,
    /// resident anonymous pages on Linux, the physical footprint on macOS.
    pub private: usize,
}

#[cfg(windows)]
pub fn os_memory() -> OsMemory {
    // GetProcessMemoryInfo (psapi.h), exported from kernel32 as
    // K32GetProcessMemoryInfo since Windows 7. WorkingSetSize is the
    // resident set; PagefileUsage is the process's commit charge, its
    // private committed memory. Source: Microsoft Learn,
    // PROCESS_MEMORY_COUNTERS structure.
    #[repr(C)]
    #[derive(Default)]
    struct ProcessMemoryCounters {
        cb: u32,
        page_fault_count: u32,
        peak_working_set_size: usize,
        working_set_size: usize,
        quota_peak_paged_pool_usage: usize,
        quota_paged_pool_usage: usize,
        quota_peak_non_paged_pool_usage: usize,
        quota_non_paged_pool_usage: usize,
        pagefile_usage: usize,
        peak_pagefile_usage: usize,
    }
    extern "system" {
        fn GetCurrentProcess() -> *mut core::ffi::c_void;
        fn K32GetProcessMemoryInfo(
            process: *mut core::ffi::c_void,
            counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
    }
    let mut counters = ProcessMemoryCounters {
        cb: std::mem::size_of::<ProcessMemoryCounters>() as u32,
        ..Default::default()
    };
    // SAFETY: the pseudo handle needs no closing and `counters` is a
    // correctly sized PROCESS_MEMORY_COUNTERS.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
    if ok == 0 {
        return OsMemory::default();
    }
    OsMemory {
        resident: counters.working_set_size,
        private: counters.pagefile_usage,
    }
}

#[cfg(target_os = "linux")]
pub fn os_memory() -> OsMemory {
    // /proc/self/status VmRSS and RssAnon, in kB (proc(5)).
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|kib| kib.parse::<usize>().ok())
            .map_or(0, |kib| kib * 1024)
    };
    OsMemory {
        resident: field("VmRSS:"),
        private: field("RssAnon:"),
    }
}

#[cfg(target_os = "macos")]
pub fn os_memory() -> OsMemory {
    // proc_pid_rusage (<libproc.h>) with the RUSAGE_INFO_V2 flavor fills a
    // struct rusage_info_v2 (<sys/resource.h>): ri_resident_size is the
    // resident set, ri_phys_footprint the memory charged to the process
    // alone, the figure Activity Monitor shows. The resident set also counts
    // the shared library pages every process maps.
    let mut info = std::mem::MaybeUninit::<libc::rusage_info_v2>::zeroed();
    // SAFETY: `info` is the buffer the V2 flavor fills, and the call writes
    // no more than that structure.
    let failed = unsafe {
        libc::proc_pid_rusage(
            libc::getpid(),
            libc::RUSAGE_INFO_V2,
            info.as_mut_ptr().cast(),
        )
    };
    if failed != 0 {
        return OsMemory::default();
    }
    // SAFETY: the call succeeded, so it filled the structure, which was
    // zeroed to begin with.
    let info = unsafe { info.assume_init() };
    OsMemory {
        resident: info.ri_resident_size as usize,
        private: info.ri_phys_footprint as usize,
    }
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn os_memory() -> OsMemory {
    OsMemory::default()
}
