//! A counting global allocator for the load instruments: live heap bytes and
//! live allocations per power-of-two size class.
//!
//! The process view (RSS) alone cannot say whether a climbing curve is memory
//! the Core still owns or memory the allocator is holding on to, which is the
//! question the soak and the idle instruments exist to answer. Every call
//! forwards to `System` unchanged; the counters only observe sizes.

// Each instrument includes this module and reads the part it reports.
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct CountingAllocator;

static LIVE_HEAP: AtomicUsize = AtomicUsize::new(0);
/// Live allocations per power-of-two size class (class `n` holds sizes in
/// `(2^(n-1), 2^n]`), so a report can name which sizes are kept.
static LIVE_BY_CLASS: [AtomicUsize; 32] = [const { AtomicUsize::new(0) }; 32];

pub fn size_class(size: usize) -> usize {
    (usize::BITS - size.saturating_sub(1).leading_zeros()).min(31) as usize
}

/// Bytes the process has allocated and not freed.
pub fn live_bytes() -> usize {
    LIVE_HEAP.load(Ordering::Relaxed)
}

/// Live allocations in size class `class`.
pub fn live_in_class(class: usize) -> usize {
    LIVE_BY_CLASS[class].load(Ordering::Relaxed)
}

// SAFETY: every call forwards to `System` unchanged; the counters only
// observe sizes.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE_HEAP.fetch_add(layout.size(), Ordering::Relaxed);
            LIVE_BY_CLASS[size_class(layout.size())].fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            LIVE_HEAP.fetch_add(layout.size(), Ordering::Relaxed);
            LIVE_BY_CLASS[size_class(layout.size())].fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE_HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
        LIVE_BY_CLASS[size_class(layout.size())].fetch_sub(1, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            LIVE_HEAP.fetch_add(new_size, Ordering::Relaxed);
            LIVE_HEAP.fetch_sub(layout.size(), Ordering::Relaxed);
            LIVE_BY_CLASS[size_class(new_size)].fetch_add(1, Ordering::Relaxed);
            LIVE_BY_CLASS[size_class(layout.size())].fetch_sub(1, Ordering::Relaxed);
        }
        moved
    }
}
