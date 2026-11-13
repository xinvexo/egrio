//! SPSC packet rings over a mapping shared with a less-privileged peer.
//!
//! Trust model: the desktop client maps the whole channel read-write, so every
//! shared byte — ring headers, descriptors, payload — can be rewritten by the
//! peer at any moment. The service side therefore:
//!
//! - captures the channel geometry (`ChannelLayout`) privately before the
//!   mapping is shared and never re-reads it from the shared header, so
//!   offsets, counts, and capacities cannot be steered;
//! - reduces every shared position modulo that private geometry before turning
//!   it into an address, so tampered head/tail values cannot move an access
//!   out of the mapping;
//! - snapshots each descriptor into a private copy (volatile read) and
//!   validates only the copy, so the checks cannot be raced;
//! - collapses any head/tail relation that violates SPSC accounting into
//!   `RingError::CorruptState` instead of trusting it.
//!
//! A hostile peer can corrupt its own packet stream or wedge its own session,
//! never redirect the service out of bounds. `tests/shared_memory_adversary.rs`
//! pins this containment.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::fmt;
use std::marker::PhantomData;
use std::ptr::{self, NonNull};
use std::sync::atomic::{fence, Ordering};

use uuid::Uuid;

use super::abi::{
    ChannelHeader, ChannelLayout, PacketDescriptor, RingHeader, CACHE_LINE_BYTES,
    CHANNEL_ABI_MAJOR, CHANNEL_ABI_MINOR, CHANNEL_MAGIC,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingError {
    WouldBlock,
    Cancelled,
    PacketTooLarge,
    CorruptState,
    InvalidHeader,
    AllocationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RingPop {
    pub packet: Vec<u8>,
    pub sequence: u64,
}
impl RingPop {
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }
}

/// The consumer's next packet, validated from a private descriptor snapshot
/// but not yet copied out: `copy_peeked` writes it straight into its
/// destination and `commit_peek` releases it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingPeek {
    pub sequence: u64,
    payload_position: u64,
    len: u32,
}

impl RingPeek {
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub struct ChannelMemory {
    base: NonNull<u8>,
    allocation: Layout,
    layout: ChannelLayout,
}

#[derive(Clone, Copy, Debug)]
pub struct ChannelBinding {
    base: NonNull<u8>,
    layout: ChannelLayout,
    channel_id: Uuid,
}

unsafe impl Send for ChannelBinding {}
unsafe impl Sync for ChannelBinding {}

impl ChannelBinding {
    /// Bind an externally owned mapping after validating its complete ABI header.
    ///
    /// # Safety
    /// `base..base+len` must remain mapped and writable for every `RingView`
    /// derived from this binding, and this process's own views must keep the
    /// SPSC producer/consumer ownership of either ring. The peer process is
    /// not trusted to do the same: its violations degrade to `CorruptState`
    /// results, not undefined behavior (see the module docs).
    pub unsafe fn from_raw(base: *mut u8, len: usize) -> Result<Self, RingError> {
        let view = ChannelView::from_raw(base, len)?;
        Ok(Self {
            base: view.base,
            layout: view.layout,
            channel_id: Uuid::from_bytes((*view.base.as_ptr().cast::<ChannelHeader>()).channel_id),
        })
    }

    /// Initialize a newly created zeroed external mapping and bind it.
    ///
    /// # Safety
    /// The caller must exclusively own a writable mapping of exactly
    /// `layout.mapping_len()` bytes and keep it alive as described by `from_raw`.
    pub unsafe fn initialize(
        base: *mut u8,
        len: usize,
        layout: ChannelLayout,
        channel_id: Uuid,
    ) -> Result<Self, RingError> {
        if len != layout.mapping_len()
            || base.is_null()
            || !(base as usize).is_multiple_of(CACHE_LINE_BYTES)
        {
            return Err(RingError::InvalidHeader);
        }
        initialize(base, layout, channel_id);
        Self::from_raw(base, len)
    }

    pub fn rx_ring(&self) -> RingView<'_> {
        unsafe { RingView::new(self.base.as_ptr(), self.layout, true) }
    }

    pub fn tx_ring(&self) -> RingView<'_> {
        unsafe { RingView::new(self.base.as_ptr(), self.layout, false) }
    }

    pub const fn channel_id(&self) -> Uuid {
        self.channel_id
    }
}

unsafe impl Send for ChannelMemory {}
unsafe impl Sync for ChannelMemory {}

impl fmt::Debug for ChannelMemory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelMemory")
            .field("layout", &self.layout)
            .finish()
    }
}

impl ChannelMemory {
    pub fn new(layout: ChannelLayout, channel_id: Uuid) -> Result<Self, RingError> {
        let allocation = Layout::from_size_align(layout.mapping_len(), CACHE_LINE_BYTES)
            .map_err(|_| RingError::AllocationFailed)?;
        let base =
            NonNull::new(unsafe { alloc_zeroed(allocation) }).ok_or(RingError::AllocationFailed)?;
        let memory = Self {
            base,
            allocation,
            layout,
        };
        unsafe { initialize(memory.base.as_ptr(), layout, channel_id) };
        Ok(memory)
    }

    pub fn from_bytes(bytes: &mut [u8]) -> Result<ChannelView<'_>, RingError> {
        ChannelView::from_raw(bytes.as_mut_ptr(), bytes.len())
    }

    pub fn rx_ring(&self) -> RingView<'_> {
        unsafe { RingView::new(self.base.as_ptr(), self.layout, true) }
    }

    pub fn tx_ring(&self) -> RingView<'_> {
        unsafe { RingView::new(self.base.as_ptr(), self.layout, false) }
    }

    pub fn binding(&self) -> ChannelBinding {
        unsafe {
            ChannelBinding::from_raw(self.base.as_ptr(), self.layout.mapping_len())
                .expect("owned channel memory has a valid ABI")
        }
    }
}

impl Drop for ChannelMemory {
    fn drop(&mut self) {
        unsafe { dealloc(self.base.as_ptr(), self.allocation) }
    }
}

#[derive(Debug)]
pub struct ChannelView<'a> {
    base: NonNull<u8>,
    layout: ChannelLayout,
    _lifetime: PhantomData<&'a mut [u8]>,
}

impl<'a> ChannelView<'a> {
    fn from_raw(base: *mut u8, len: usize) -> Result<Self, RingError> {
        if base.is_null()
            || !(base as usize).is_multiple_of(CACHE_LINE_BYTES)
            || len < std::mem::size_of::<ChannelHeader>()
        {
            return Err(RingError::InvalidHeader);
        }
        let header = unsafe { &*(base.cast::<ChannelHeader>()) };
        let layout = validate_header(header, len)?;
        Ok(Self {
            base: NonNull::new(base).unwrap(),
            layout,
            _lifetime: PhantomData,
        })
    }

    pub fn rx_ring(&self) -> RingView<'_> {
        unsafe { RingView::new(self.base.as_ptr(), self.layout, true) }
    }
    pub fn tx_ring(&self) -> RingView<'_> {
        unsafe { RingView::new(self.base.as_ptr(), self.layout, false) }
    }
}

#[derive(Clone, Copy)]
pub struct RingView<'a> {
    header: NonNull<RingHeader>,
    descriptors: NonNull<PacketDescriptor>,
    payload: NonNull<u8>,
    descriptor_count: u64,
    payload_capacity: u64,
    max_packet_bytes: u32,
    _lifetime: PhantomData<&'a [u8]>,
}

unsafe impl Send for RingView<'_> {}
unsafe impl Sync for RingView<'_> {}

impl fmt::Debug for RingView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RingView")
            .field("descriptor_count", &self.descriptor_count)
            .field("payload_capacity", &self.payload_capacity)
            .finish()
    }
}

impl<'a> RingView<'a> {
    unsafe fn new(base: *mut u8, layout: ChannelLayout, rx: bool) -> Self {
        let (header, descriptors, payload) = if rx {
            (
                layout.rx_ring_header_offset(),
                layout.rx_descriptors_offset(),
                layout.rx_payload_offset(),
            )
        } else {
            (
                layout.tx_ring_header_offset(),
                layout.tx_descriptors_offset(),
                layout.tx_payload_offset(),
            )
        };
        Self {
            header: NonNull::new_unchecked(base.add(header).cast()),
            descriptors: NonNull::new_unchecked(base.add(descriptors).cast()),
            payload: NonNull::new_unchecked(base.add(payload)),
            descriptor_count: u64::from(layout.descriptor_count()),
            payload_capacity: layout.payload_arena_bytes(),
            max_packet_bytes: layout.max_packet_bytes(),
            _lifetime: PhantomData,
        }
    }

    fn header(&self) -> &RingHeader {
        unsafe { self.header.as_ref() }
    }

    pub fn try_push(&self, packet: &[u8]) -> Result<(), RingError> {
        self.try_push_parts(&[packet])
    }

    /// Pushes one packet given as consecutive parts, copying each straight
    /// into the ring.
    pub fn try_push_parts(&self, parts: &[&[u8]]) -> Result<(), RingError> {
        let total: usize = parts.iter().map(|part| part.len()).sum();
        let len = u64::try_from(total).map_err(|_| RingError::PacketTooLarge)?;
        if len == 0 || len > u64::from(self.max_packet_bytes) {
            return Err(RingError::PacketTooLarge);
        }
        let header = self.header();
        let descriptor_head = header.descriptor_head.load(Ordering::Relaxed);
        let descriptor_tail = header.descriptor_tail.load(Ordering::Acquire);
        let payload_head = header.payload_head.load(Ordering::Relaxed);
        let payload_tail = header.payload_tail.load(Ordering::Acquire);
        let descriptor_used = descriptor_head
            .checked_sub(descriptor_tail)
            .ok_or(RingError::CorruptState)?;
        let payload_used = payload_head
            .checked_sub(payload_tail)
            .ok_or(RingError::CorruptState)?;
        if descriptor_used > self.descriptor_count || payload_used > self.payload_capacity {
            return Err(RingError::CorruptState);
        }
        if descriptor_used == self.descriptor_count || len > self.payload_capacity - payload_used {
            return Err(RingError::WouldBlock);
        }
        // Offsets within the arena: the peer can park `payload_head` anywhere,
        // so the parts advance from its reduced position, which cannot
        // overflow.
        let mut position = payload_head % self.payload_capacity;
        for part in parts {
            unsafe { copy_into_ring(self.payload.as_ptr(), self.payload_capacity, position, part) };
            position = (position + part.len() as u64) % self.payload_capacity;
        }
        let descriptor = PacketDescriptor {
            sequence: descriptor_head,
            payload_position: payload_head,
            payload_len: total as u32,
            flags: 0,
        };
        // Volatile: the slot lives in peer-writable shared memory, so keep the
        // publish an actual store; the Release store on `descriptor_head` below
        // is what orders it for an honest consumer.
        unsafe {
            ptr::write_volatile(
                self.descriptors
                    .as_ptr()
                    .add((descriptor_head % self.descriptor_count) as usize),
                descriptor,
            )
        };
        let next_payload_head = payload_head
            .checked_add(len)
            .ok_or(RingError::CorruptState)?;
        let next_descriptor_head = descriptor_head
            .checked_add(1)
            .ok_or(RingError::CorruptState)?;
        header
            .payload_head
            .store(next_payload_head, Ordering::Release);
        header
            .descriptor_head
            .store(next_descriptor_head, Ordering::Release);
        Ok(())
    }

    /// Consumer side, before parking on the data event: raises
    /// `consumer_waiting` and returns whether the ring is still empty. On
    /// `false` data arrived meanwhile and the caller pops instead of parking.
    ///
    /// The flag store and the producer's head store are each followed by a
    /// SeqCst fence before the other side's read, so at least one side sees
    /// the other: either this re-check finds the packet, or the producer finds
    /// the flag and signals. A stale signal only makes a later park return at
    /// once, and the caller re-checks.
    pub fn begin_consumer_wait(&self) -> bool {
        let header = self.header();
        header.consumer_waiting.store(1, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        let empty = header.descriptor_head.load(Ordering::Acquire)
            == header.descriptor_tail.load(Ordering::Relaxed);
        if !empty {
            header.consumer_waiting.store(0, Ordering::Relaxed);
        }
        empty
    }

    /// Producer side, after a push: whether the consumer waits and must be
    /// signaled. Clears the flag, so one push signals per wait.
    pub fn consumer_needs_wake(&self) -> bool {
        fence(Ordering::SeqCst);
        let header = self.header();
        header.consumer_waiting.load(Ordering::Relaxed) != 0
            && header.consumer_waiting.swap(0, Ordering::SeqCst) != 0
    }

    /// Producer side, before parking on the space event: raises
    /// `producer_waiting` and returns whether the ring is still above the low
    /// watermark. On `false` it drained meanwhile and the caller pushes again.
    pub fn begin_producer_wait(&self) -> bool {
        let header = self.header();
        header.producer_waiting.store(1, Ordering::SeqCst);
        fence(Ordering::SeqCst);
        let park = !self.drained_to_low_watermark();
        if !park {
            header.producer_waiting.store(0, Ordering::Relaxed);
        }
        park
    }

    /// Consumer side, after a pop: whether a waiting producer must be
    /// signaled, which happens once the ring drained to the low watermark, so
    /// a parked producer wakes once per half ring instead of once per packet.
    pub fn producer_needs_wake(&self) -> bool {
        fence(Ordering::SeqCst);
        let header = self.header();
        header.producer_waiting.load(Ordering::Relaxed) != 0
            && self.drained_to_low_watermark()
            && header.producer_waiting.swap(0, Ordering::SeqCst) != 0
    }

    /// Whether at most half the descriptors and half the payload arena are in
    /// use, with room left for the largest packet, so a woken producer's next
    /// push fits. Cursors a peer corrupted count as drained: the producer then
    /// retries and meets the corruption itself instead of sleeping forever.
    fn drained_to_low_watermark(&self) -> bool {
        let header = self.header();
        let descriptors = header
            .descriptor_head
            .load(Ordering::Acquire)
            .checked_sub(header.descriptor_tail.load(Ordering::Acquire));
        let payload = header
            .payload_head
            .load(Ordering::Acquire)
            .checked_sub(header.payload_tail.load(Ordering::Acquire));
        let payload_mark = (self.payload_capacity / 2)
            .min(self.payload_capacity - u64::from(self.max_packet_bytes));
        match (descriptors, payload) {
            (Some(descriptors), Some(payload)) => {
                descriptors <= self.descriptor_count / 2 && payload <= payload_mark
            }
            _ => true,
        }
    }

    /// Pushes one packet, parking on `wait_for_space` while the ring holds
    /// more than the low watermark, and signals `notify_data` when the
    /// consumer waits.
    pub fn push_until<W, N, C>(
        &self,
        packet: &[u8],
        mut wait_for_space: W,
        mut notify_data: N,
        mut cancelled: C,
    ) -> Result<(), RingError>
    where
        W: FnMut() -> Result<(), RingError>,
        N: FnMut() -> Result<(), RingError>,
        C: FnMut() -> bool,
    {
        loop {
            match self.try_push(packet) {
                Ok(()) => {
                    if self.consumer_needs_wake() {
                        notify_data()?;
                    }
                    return Ok(());
                }
                Err(RingError::WouldBlock) if cancelled() => return Err(RingError::Cancelled),
                Err(RingError::WouldBlock) => {
                    if self.begin_producer_wait() {
                        wait_for_space()?;
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub fn try_pop(&self) -> Result<RingPop, RingError> {
        let peek = self.try_peek()?;
        let mut packet = Vec::with_capacity(peek.len());
        // SAFETY: the copy initializes all `peek.len()` bytes before `set_len`.
        unsafe {
            self.copy_peeked_to(&peek, packet.as_mut_ptr());
            packet.set_len(peek.len());
        }
        self.commit_peek(&peek)?;
        Ok(RingPop {
            packet,
            sequence: peek.sequence,
        })
    }

    pub fn try_peek(&self) -> Result<RingPeek, RingError> {
        let header = self.header();
        let descriptor_tail = header.descriptor_tail.load(Ordering::Relaxed);
        let descriptor_head = header.descriptor_head.load(Ordering::Acquire);
        if descriptor_tail == descriptor_head {
            return Err(RingError::WouldBlock);
        }
        if descriptor_head
            .checked_sub(descriptor_tail)
            .ok_or(RingError::CorruptState)?
            > self.descriptor_count
        {
            return Err(RingError::CorruptState);
        }
        // Snapshot the descriptor once into a private copy (volatile: the peer
        // can rewrite the slot concurrently) and validate only the copy, so
        // the checks below cannot be raced against the shared slot.
        let descriptor = unsafe {
            ptr::read_volatile(
                self.descriptors
                    .as_ptr()
                    .add((descriptor_tail % self.descriptor_count) as usize),
            )
        };
        let payload_tail = header.payload_tail.load(Ordering::Relaxed);
        if descriptor.sequence != descriptor_tail
            || descriptor.payload_position != payload_tail
            || descriptor.payload_len == 0
            || descriptor.payload_len > self.max_packet_bytes
        {
            return Err(RingError::CorruptState);
        }
        Ok(RingPeek {
            sequence: descriptor.sequence,
            payload_position: descriptor.payload_position,
            len: descriptor.payload_len,
        })
    }

    /// Copies the peeked packet into `destination`, which must be exactly
    /// `peek.len()` bytes; the packet stays queued until `commit_peek`.
    pub fn copy_peeked(&self, peek: &RingPeek, destination: &mut [u8]) {
        assert_eq!(destination.len(), peek.len(), "peeked packet length");
        // SAFETY: `destination` holds exactly `peek.len()` writable bytes.
        unsafe { self.copy_peeked_to(peek, destination.as_mut_ptr()) }
    }

    /// # Safety
    /// `destination` must be valid for `peek.len()` byte writes.
    unsafe fn copy_peeked_to(&self, peek: &RingPeek, destination: *mut u8) {
        copy_from_ring(
            self.payload.as_ptr(),
            self.payload_capacity,
            peek.payload_position,
            peek.len(),
            destination,
        )
    }

    pub fn commit_peek(&self, peek: &RingPeek) -> Result<(), RingError> {
        let header = self.header();
        let descriptor_tail = header.descriptor_tail.load(Ordering::Relaxed);
        let payload_tail = header.payload_tail.load(Ordering::Relaxed);
        if descriptor_tail != peek.sequence || payload_tail != peek.payload_position {
            return Err(RingError::CorruptState);
        }
        let next_payload_tail = payload_tail
            .checked_add(u64::from(peek.len))
            .ok_or(RingError::CorruptState)?;
        let next_descriptor_tail = descriptor_tail
            .checked_add(1)
            .ok_or(RingError::CorruptState)?;
        header
            .payload_tail
            .store(next_payload_tail, Ordering::Release);
        header
            .descriptor_tail
            .store(next_descriptor_tail, Ordering::Release);
        Ok(())
    }

    pub fn pop_until<W, N, C>(
        &self,
        wait_for_data: W,
        notify_space: N,
        cancelled: C,
    ) -> Result<Vec<u8>, RingError>
    where
        W: FnMut() -> Result<(), RingError>,
        N: FnMut() -> Result<(), RingError>,
        C: FnMut() -> bool,
    {
        self.pop_entry_until(wait_for_data, notify_space, cancelled)
            .map(|entry| entry.packet)
    }

    pub fn pop_entry_until<W, N, C>(
        &self,
        mut wait_for_data: W,
        mut notify_space: N,
        mut cancelled: C,
    ) -> Result<RingPop, RingError>
    where
        W: FnMut() -> Result<(), RingError>,
        N: FnMut() -> Result<(), RingError>,
        C: FnMut() -> bool,
    {
        loop {
            match self.try_pop() {
                Ok(result) => {
                    if self.producer_needs_wake() {
                        notify_space()?;
                    }
                    return Ok(result);
                }
                Err(RingError::WouldBlock) if cancelled() => return Err(RingError::Cancelled),
                Err(RingError::WouldBlock) => {
                    if self.begin_consumer_wait() {
                        wait_for_data()?;
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
}

unsafe fn initialize(base: *mut u8, layout: ChannelLayout, channel_id: Uuid) {
    ptr::write(
        base.cast::<ChannelHeader>(),
        ChannelHeader {
            magic: CHANNEL_MAGIC,
            abi_major: CHANNEL_ABI_MAJOR,
            abi_minor: CHANNEL_ABI_MINOR,
            header_size: std::mem::size_of::<ChannelHeader>() as u32,
            mapping_len: layout.mapping_len() as u64,
            channel_id: *channel_id.as_bytes(),
            descriptor_count: layout.descriptor_count(),
            max_packet_bytes: layout.max_packet_bytes(),
            payload_arena_bytes: layout.payload_arena_bytes(),
            rx_ring_header_offset: layout.rx_ring_header_offset() as u64,
            rx_descriptors_offset: layout.rx_descriptors_offset() as u64,
            rx_payload_offset: layout.rx_payload_offset() as u64,
            tx_ring_header_offset: layout.tx_ring_header_offset() as u64,
            tx_descriptors_offset: layout.tx_descriptors_offset() as u64,
            tx_payload_offset: layout.tx_payload_offset() as u64,
        },
    );
    ptr::write(
        base.add(layout.rx_ring_header_offset()).cast(),
        RingHeader::new(),
    );
    ptr::write(
        base.add(layout.tx_ring_header_offset()).cast(),
        RingHeader::new(),
    );
}

fn validate_header(header: &ChannelHeader, len: usize) -> Result<ChannelLayout, RingError> {
    if header.magic != CHANNEL_MAGIC
        || header.abi_major != CHANNEL_ABI_MAJOR
        || header.header_size as usize != std::mem::size_of::<ChannelHeader>()
    {
        return Err(RingError::InvalidHeader);
    }
    let layout = ChannelLayout::new(
        header.descriptor_count,
        header.payload_arena_bytes,
        header.max_packet_bytes,
    )
    .map_err(|_| RingError::InvalidHeader)?;
    if header.mapping_len as usize != len
        || layout.mapping_len() != len
        || header.rx_ring_header_offset as usize != layout.rx_ring_header_offset()
        || header.rx_descriptors_offset as usize != layout.rx_descriptors_offset()
        || header.rx_payload_offset as usize != layout.rx_payload_offset()
        || header.tx_ring_header_offset as usize != layout.tx_ring_header_offset()
        || header.tx_descriptors_offset as usize != layout.tx_descriptors_offset()
        || header.tx_payload_offset as usize != layout.tx_payload_offset()
    {
        return Err(RingError::InvalidHeader);
    }
    Ok(layout)
}

/// `position` comes from peer-writable shared memory: the modulo keeps every
/// byte of the copy inside `[base, base + capacity)` no matter its value, and
/// the caller validated `bytes.len() <= max_packet_bytes <= capacity`, which
/// bounds the wrapped remainder.
unsafe fn copy_into_ring(base: *mut u8, capacity: u64, position: u64, bytes: &[u8]) {
    let offset = (position % capacity) as usize;
    let first = bytes.len().min(capacity as usize - offset);
    ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), first);
    if first < bytes.len() {
        ptr::copy_nonoverlapping(bytes.as_ptr().add(first), base, bytes.len() - first);
    }
}

/// Same containment as `copy_into_ring`: the untrusted `position` is reduced
/// modulo the private capacity and the caller validated `len` against
/// `max_packet_bytes`, so the copy cannot leave the payload arena.
unsafe fn copy_from_ring(
    base: *mut u8,
    capacity: u64,
    position: u64,
    len: usize,
    destination: *mut u8,
) {
    let offset = (position % capacity) as usize;
    let first = len.min(capacity as usize - offset);
    ptr::copy_nonoverlapping(base.add(offset), destination, first);
    if first < len {
        ptr::copy_nonoverlapping(base, destination.add(first), len - first);
    }
}
