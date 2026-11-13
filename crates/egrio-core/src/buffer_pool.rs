//! Fixed-size byte buffers lent to data paths only while they hold bytes.
//!
//! A relay direction or a UDP datagram borrows a buffer when bytes arrive
//! and returns it once they have been passed on, so an idle connection holds
//! none. Each pool keeps up to `retain` returned buffers for the next
//! borrower; beyond that they go back to the allocator, which bounds what an
//! idle process keeps.
//!
//! `retain` has to cover the borrowers asking at once, or a borrow allocates
//! and zeroes the whole buffer again -- and it is also the only bound on
//! what the pools hold while nothing is moving, so it cannot simply be
//! large. Use the `buffer_pools` counters in `e2e_udp_throughput` and
//! `e2e_throughput` to compare retention against concurrent borrowers.
//!
//! The UDP read pool's borrowers are the capture queues' pumps (one buffer
//! each while inside a drain) and the session actors' reads. A capture with
//! many queues can have every pump inside a drain at the same moment.
//!
//! The relay pool's borrowers are the directions holding bytes, and a
//! direction holds its buffer only while it has some, rather than for the
//! length of the connection. Concurrent demand follows the threads running,
//! not the sessions open.

use std::ops::{Deref, DerefMut};
#[cfg(any(test, feature = "bench-internals"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

pub(crate) struct BufferPool {
    size: usize,
    retain: usize,
    free: Mutex<Vec<Box<[u8]>>>,
    #[cfg(test)]
    lent: AtomicUsize,
    /// Borrows served from `free`, and borrows that had to allocate: what
    /// says whether `retain` covers the borrowers asking at once. Kept for
    /// the tests and for the instruments, never in a shipped build.
    #[cfg(any(test, feature = "bench-internals"))]
    borrows: (AtomicUsize, AtomicUsize),
}

impl BufferPool {
    pub(crate) const fn new(size: usize, retain: usize) -> Self {
        Self {
            size,
            retain,
            free: Mutex::new(Vec::new()),
            #[cfg(test)]
            lent: AtomicUsize::new(0),
            #[cfg(any(test, feature = "bench-internals"))]
            borrows: (AtomicUsize::new(0), AtomicUsize::new(0)),
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// A buffer of `size` bytes whose contents are unspecified.
    pub(crate) fn take(&'static self) -> PooledBuffer {
        // The guard ends with its own statement. Held across the fallback it
        // would put a `size`-byte allocation and its zeroing inside the
        // critical section, which every other borrower waits behind, and a
        // pool whose free list is shorter than the borrowers asking at once
        // takes that path on every borrow.
        let free = self
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        #[cfg(any(test, feature = "bench-internals"))]
        match &free {
            Some(_) => self.borrows.0.fetch_add(1, Ordering::Relaxed),
            None => self.borrows.1.fetch_add(1, Ordering::Relaxed),
        };
        let buffer = free.unwrap_or_else(|| vec![0; self.size].into_boxed_slice());
        #[cfg(test)]
        self.lent.fetch_add(1, Ordering::Relaxed);
        PooledBuffer { pool: self, buffer }
    }

    /// Buffers currently borrowed.
    #[cfg(test)]
    pub(crate) fn lent(&self) -> usize {
        self.lent.load(Ordering::Relaxed)
    }

    /// Borrows served from the free list, and borrows that had to allocate
    /// and zero a whole buffer.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn borrows(&self) -> (usize, usize) {
        (
            self.borrows.0.load(Ordering::Relaxed),
            self.borrows.1.load(Ordering::Relaxed),
        )
    }

    /// Returned buffers waiting for a borrower.
    #[cfg(test)]
    pub(crate) fn retained(&self) -> usize {
        self.free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn give_back(&self, buffer: Box<[u8]>) {
        #[cfg(test)]
        self.lent.fetch_sub(1, Ordering::Relaxed);
        let mut free = self.free.lock().unwrap_or_else(PoisonError::into_inner);
        if free.len() < self.retain {
            free.push(buffer);
        }
    }
}

/// A borrowed buffer; dropping it returns it to its pool.
pub(crate) struct PooledBuffer {
    pool: &'static BufferPool,
    buffer: Box<[u8]>,
}

impl Deref for PooledBuffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buffer
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.pool.give_back(std::mem::take(&mut self.buffer));
    }
}

impl std::fmt::Debug for PooledBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledBuffer")
            .field("len", &self.buffer.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returned_buffers_are_reused_up_to_the_retain_bound() {
        static POOL: BufferPool = BufferPool::new(16, 2);
        let buffers: Vec<_> = (0..3).map(|_| POOL.take()).collect();
        assert!(buffers.iter().all(|buffer| buffer.len() == 16));
        assert_eq!((POOL.lent(), POOL.retained()), (3, 0));

        drop(buffers);
        assert_eq!(POOL.lent(), 0);
        assert_eq!(
            POOL.retained(),
            2,
            "the third buffer goes back to the allocator"
        );

        let reused = POOL.take();
        assert_eq!(POOL.retained(), 1);
        drop(reused);
        assert_eq!(POOL.retained(), 2);

        // What the instruments read: three borrows found nothing to reuse
        // and had to allocate, the fourth was served from the free list.
        assert_eq!(POOL.borrows(), (1, 3));
    }
}
