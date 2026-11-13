//! Hostile-peer containment for the shared packet ring.
//!
//! The desktop client maps the whole channel read-write, so every shared byte
//! — headers, descriptors, cursors, payload — is attacker-writable. These
//! tests replay that access from the raw byte side and pin the service-side
//! guarantees documented in `shared_memory/ring.rs`: tampering degrades to
//! `CorruptState` or garbage confined to the mapping, never to out-of-bounds
//! access or peer-steered geometry. A canary region after the mapping catches
//! an escape even without a sanitizer.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::sync::atomic::Ordering;

use egrio_service::shared_memory::{
    ChannelBinding, ChannelHeader, ChannelLayout, PacketDescriptor, RingError, RingHeader,
};
use uuid::Uuid;

const CANARY: u8 = 0x5A;
const CANARY_BYTES: usize = 4096;

/// An aligned stand-in for the shared file mapping, with a canary tail.
struct SharedMapping {
    base: *mut u8,
    len: usize,
    allocation: Layout,
}

impl SharedMapping {
    fn new(layout: &ChannelLayout) -> Self {
        let len = layout.mapping_len();
        let allocation =
            Layout::from_size_align(len + CANARY_BYTES, 64).expect("mapping allocation layout");
        let base = unsafe { alloc_zeroed(allocation) };
        assert!(!base.is_null(), "aligned mapping allocation");
        unsafe { std::ptr::write_bytes(base.add(len), CANARY, CANARY_BYTES) };
        Self {
            base,
            len,
            allocation,
        }
    }

    fn assert_canary_intact(&self) {
        let canary = unsafe { std::slice::from_raw_parts(self.base.add(self.len), CANARY_BYTES) };
        assert!(
            canary.iter().all(|byte| *byte == CANARY),
            "a ring operation escaped the shared mapping"
        );
    }
}

impl Drop for SharedMapping {
    fn drop(&mut self) {
        unsafe { dealloc(self.base, self.allocation) };
    }
}

fn armed_channel(layout: ChannelLayout) -> (SharedMapping, ChannelBinding) {
    let mapping = SharedMapping::new(&layout);
    let binding = unsafe {
        ChannelBinding::initialize(
            mapping.base,
            layout.mapping_len(),
            layout,
            Uuid::from_u128(0xd15),
        )
    }
    .expect("initialize channel");
    (mapping, binding)
}

/// The attacker's raw view of one ring's header block.
fn ring_header(mapping: &SharedMapping, offset: usize) -> &RingHeader {
    unsafe { &*(mapping.base.add(offset).cast::<RingHeader>()) }
}

#[test]
fn tampered_cursors_fail_closed_without_leaving_the_mapping() {
    let layout = ChannelLayout::new(4, 64, 16).expect("layout");
    let (mapping, binding) = armed_channel(layout);

    // Consumer-side sabotage of the RX ring the service produces into.
    let rx = ring_header(&mapping, layout.rx_ring_header_offset());
    rx.descriptor_head.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        binding.rx_ring().try_push(&[1]).unwrap_err(),
        RingError::CorruptState,
        "descriptor accounting beyond the ring is rejected"
    );
    rx.descriptor_head.store(0, Ordering::Relaxed);
    rx.descriptor_tail.store(1, Ordering::Relaxed);
    assert_eq!(
        binding.rx_ring().try_push(&[1]).unwrap_err(),
        RingError::CorruptState,
        "a tail ahead of its head is rejected"
    );
    rx.descriptor_tail.store(0, Ordering::Relaxed);
    rx.payload_head.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        binding.rx_ring().try_push(&[1]).unwrap_err(),
        RingError::CorruptState,
        "payload accounting beyond the arena is rejected"
    );
    // Both payload cursors at the far end: usage looks sane, but advancing the
    // head would overflow, and the checked add turns that into corruption.
    rx.payload_tail.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        binding.rx_ring().try_push(&[1]).unwrap_err(),
        RingError::CorruptState,
        "a cursor advance that would overflow is rejected"
    );

    // Producer-side sabotage of the TX ring the service consumes from.
    let tx = ring_header(&mapping, layout.tx_ring_header_offset());
    tx.descriptor_head.store(u64::MAX, Ordering::Relaxed);
    assert_eq!(
        binding.tx_ring().try_peek().unwrap_err(),
        RingError::CorruptState
    );
    tx.descriptor_head.store(0, Ordering::Relaxed);
    tx.descriptor_tail.store(1, Ordering::Relaxed);
    assert_eq!(
        binding.tx_ring().try_peek().unwrap_err(),
        RingError::CorruptState
    );

    mapping.assert_canary_intact();
}

#[test]
fn hostile_descriptors_are_rejected_from_the_private_snapshot() {
    let layout = ChannelLayout::new(4, 64, 16).expect("layout");
    let (mapping, binding) = armed_channel(layout);
    let tx = ring_header(&mapping, layout.tx_ring_header_offset());
    let descriptors = unsafe {
        mapping
            .base
            .add(layout.tx_descriptors_offset())
            .cast::<PacketDescriptor>()
    };
    let hostile = |descriptor: PacketDescriptor| {
        unsafe { descriptors.write(descriptor) };
        binding.tx_ring().try_peek().unwrap_err()
    };
    tx.payload_head.store(64, Ordering::Relaxed);
    tx.descriptor_head.store(1, Ordering::Release);

    // A length far past the packet bound is refused before anything is sized
    // from it; zero-length and identity-mismatched entries are equally dead.
    for descriptor in [
        PacketDescriptor {
            sequence: 0,
            payload_position: 0,
            payload_len: u32::MAX,
            flags: 0,
        },
        PacketDescriptor {
            sequence: 0,
            payload_position: 0,
            payload_len: 0,
            flags: 0,
        },
        PacketDescriptor {
            sequence: 7,
            payload_position: 0,
            payload_len: 4,
            flags: 0,
        },
        PacketDescriptor {
            sequence: 0,
            payload_position: 9,
            payload_len: 4,
            flags: 0,
        },
    ] {
        assert_eq!(hostile(descriptor), RingError::CorruptState);
    }

    mapping.assert_canary_intact();
}

#[test]
fn a_commit_raced_by_the_peer_surfaces_corruption_instead_of_desync() {
    let layout = ChannelLayout::new(4, 64, 16).expect("layout");
    let (mapping, binding) = armed_channel(layout);
    binding.tx_ring().try_push(&[1, 2, 3]).expect("honest push");
    let peek = binding.tx_ring().try_peek().expect("peek");

    // The peer yanks the consumer tail between peek and commit.
    let tx = ring_header(&mapping, layout.tx_ring_header_offset());
    tx.descriptor_tail.store(3, Ordering::Relaxed);
    assert_eq!(
        binding.tx_ring().commit_peek(&peek).unwrap_err(),
        RingError::CorruptState
    );

    mapping.assert_canary_intact();
}

#[test]
fn rewriting_the_shared_header_cannot_steer_bound_geometry() {
    let layout = ChannelLayout::new(4, 64, 16).expect("layout");
    let (mapping, binding) = armed_channel(layout);

    // Torch the entire ChannelHeader after binding: descriptor count, offsets,
    // and capacities all become garbage. A binding that re-read shared
    // geometry would divide by zero or walk out of the mapping; the real one
    // captured the layout privately and keeps working.
    unsafe { std::ptr::write_bytes(mapping.base, 0xFF, std::mem::size_of::<ChannelHeader>()) };
    binding.rx_ring().try_push(&[42; 16]).expect("push");
    assert_eq!(
        binding.rx_ring().try_pop().expect("pop").packet(),
        &[42; 16]
    );

    mapping.assert_canary_intact();
}

#[test]
fn far_wrapped_cursors_stay_inside_the_payload_arena() {
    let layout = ChannelLayout::new(4, 64, 16).expect("layout");
    let (mapping, binding) = armed_channel(layout);

    // The peer parks every cursor at a huge position that wraps mid-packet
    // (offset 56 of a 64-byte arena). Each access is reduced modulo the
    // private capacity, so the packet round-trips through the wrap and the
    // canary proves nothing escaped.
    let far = (1_u64 << 62) + 56;
    let rx = ring_header(&mapping, layout.rx_ring_header_offset());
    rx.descriptor_head.store(far, Ordering::Relaxed);
    rx.descriptor_tail.store(far, Ordering::Relaxed);
    rx.payload_head.store(far, Ordering::Relaxed);
    rx.payload_tail.store(far, Ordering::Relaxed);

    let packet: Vec<u8> = (0..16).collect();
    binding.rx_ring().try_push(&packet).expect("wrapped push");
    let popped = binding.rx_ring().try_pop().expect("wrapped pop");
    assert_eq!(popped.packet(), packet.as_slice());
    assert_eq!(popped.sequence, far);

    mapping.assert_canary_intact();
}
