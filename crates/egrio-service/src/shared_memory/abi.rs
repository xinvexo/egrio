use std::mem::{align_of, size_of};
use std::sync::atomic::AtomicU64;

pub const CHANNEL_MAGIC: [u8; 8] = *b"EGRPKT01";
pub const CHANNEL_ABI_MAJOR: u16 = 2;
pub const CHANNEL_ABI_MINOR: u16 = 0;
pub const DESCRIPTOR_COUNT: u32 = 4096;
pub const PAYLOAD_ARENA_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PACKET_BYTES: u32 = 65_535;
pub const CACHE_LINE_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    InvalidDescriptorCount,
    InvalidPayloadCapacity,
    InvalidPacketSize,
    Overflow,
}

#[repr(C, align(64))]
pub struct ChannelHeader {
    pub magic: [u8; 8],
    pub abi_major: u16,
    pub abi_minor: u16,
    pub header_size: u32,
    pub mapping_len: u64,
    pub channel_id: [u8; 16],
    pub descriptor_count: u32,
    pub max_packet_bytes: u32,
    pub payload_arena_bytes: u64,
    pub rx_ring_header_offset: u64,
    pub rx_descriptors_offset: u64,
    pub rx_payload_offset: u64,
    pub tx_ring_header_offset: u64,
    pub tx_descriptors_offset: u64,
    pub tx_payload_offset: u64,
}

/// One ring's cursors and wait flags. A side about to park on its event
/// raises its flag first; the other side signals that event only while the
/// flag is up, and space only once the ring drained to the low watermark.
#[repr(C, align(64))]
pub struct RingHeader {
    pub descriptor_head: AtomicU64,
    pub descriptor_tail: AtomicU64,
    pub payload_head: AtomicU64,
    pub payload_tail: AtomicU64,
    /// Nonzero while the consumer waits for data.
    pub consumer_waiting: AtomicU64,
    /// Nonzero while the producer waits for space.
    pub producer_waiting: AtomicU64,
    pub reserved: [u8; 16],
}

impl Default for RingHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl RingHeader {
    pub fn new() -> Self {
        Self {
            descriptor_head: AtomicU64::new(0),
            descriptor_tail: AtomicU64::new(0),
            payload_head: AtomicU64::new(0),
            payload_tail: AtomicU64::new(0),
            consumer_waiting: AtomicU64::new(0),
            producer_waiting: AtomicU64::new(0),
            reserved: [0; 16],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PacketDescriptor {
    pub sequence: u64,
    pub payload_position: u64,
    pub payload_len: u32,
    pub flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelLayout {
    descriptor_count: u32,
    payload_arena_bytes: u64,
    max_packet_bytes: u32,
    rx_ring_header_offset: usize,
    rx_descriptors_offset: usize,
    rx_payload_offset: usize,
    tx_ring_header_offset: usize,
    tx_descriptors_offset: usize,
    tx_payload_offset: usize,
    mapping_len: usize,
}

impl ChannelLayout {
    pub fn standard() -> Result<Self, LayoutError> {
        Self::new(DESCRIPTOR_COUNT, PAYLOAD_ARENA_BYTES, MAX_PACKET_BYTES)
    }

    pub fn new(
        descriptor_count: u32,
        payload_arena_bytes: u64,
        max_packet_bytes: u32,
    ) -> Result<Self, LayoutError> {
        if descriptor_count == 0 || !descriptor_count.is_power_of_two() {
            return Err(LayoutError::InvalidDescriptorCount);
        }
        if max_packet_bytes == 0 || max_packet_bytes > MAX_PACKET_BYTES {
            return Err(LayoutError::InvalidPacketSize);
        }
        if payload_arena_bytes < u64::from(max_packet_bytes) {
            return Err(LayoutError::InvalidPayloadCapacity);
        }
        let payload = usize::try_from(payload_arena_bytes).map_err(|_| LayoutError::Overflow)?;
        let descriptors = usize::try_from(descriptor_count)
            .map_err(|_| LayoutError::Overflow)?
            .checked_mul(size_of::<PacketDescriptor>())
            .ok_or(LayoutError::Overflow)?;
        let rx_ring_header_offset = align_up(size_of::<ChannelHeader>(), CACHE_LINE_BYTES)?;
        let rx_descriptors_offset = rx_ring_header_offset
            .checked_add(size_of::<RingHeader>())
            .ok_or(LayoutError::Overflow)?;
        let rx_payload_offset = rx_descriptors_offset
            .checked_add(descriptors)
            .ok_or(LayoutError::Overflow)?;
        let tx_ring_header_offset = align_up(
            rx_payload_offset
                .checked_add(payload)
                .ok_or(LayoutError::Overflow)?,
            CACHE_LINE_BYTES,
        )?;
        let tx_descriptors_offset = tx_ring_header_offset
            .checked_add(size_of::<RingHeader>())
            .ok_or(LayoutError::Overflow)?;
        let tx_payload_offset = tx_descriptors_offset
            .checked_add(descriptors)
            .ok_or(LayoutError::Overflow)?;
        let mapping_len = tx_payload_offset
            .checked_add(payload)
            .ok_or(LayoutError::Overflow)?;
        debug_assert_eq!(align_of::<ChannelHeader>(), CACHE_LINE_BYTES);
        Ok(Self {
            descriptor_count,
            payload_arena_bytes,
            max_packet_bytes,
            rx_ring_header_offset,
            rx_descriptors_offset,
            rx_payload_offset,
            tx_ring_header_offset,
            tx_descriptors_offset,
            tx_payload_offset,
            mapping_len,
        })
    }

    pub const fn descriptor_count(self) -> u32 {
        self.descriptor_count
    }
    pub const fn payload_arena_bytes(self) -> u64 {
        self.payload_arena_bytes
    }
    pub const fn max_packet_bytes(self) -> u32 {
        self.max_packet_bytes
    }
    pub const fn rx_ring_header_offset(self) -> usize {
        self.rx_ring_header_offset
    }
    pub const fn rx_descriptors_offset(self) -> usize {
        self.rx_descriptors_offset
    }
    pub const fn rx_payload_offset(self) -> usize {
        self.rx_payload_offset
    }
    pub const fn tx_ring_header_offset(self) -> usize {
        self.tx_ring_header_offset
    }
    pub const fn tx_descriptors_offset(self) -> usize {
        self.tx_descriptors_offset
    }
    pub const fn tx_payload_offset(self) -> usize {
        self.tx_payload_offset
    }
    pub const fn mapping_len(self) -> usize {
        self.mapping_len
    }
    pub const fn rx_payload_end(self) -> usize {
        self.rx_payload_offset + self.payload_arena_bytes as usize
    }
    pub const fn tx_payload_end(self) -> usize {
        self.tx_payload_offset + self.payload_arena_bytes as usize
    }
}

fn align_up(value: usize, alignment: usize) -> Result<usize, LayoutError> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(LayoutError::Overflow)
}
