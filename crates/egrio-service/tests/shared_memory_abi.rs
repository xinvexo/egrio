use std::mem::{align_of, size_of};

use egrio_service::shared_memory::{
    ChannelBinding, ChannelHeader, ChannelLayout, PacketDescriptor, RingHeader, CHANNEL_ABI_MAJOR,
    CHANNEL_ABI_MINOR, CHANNEL_MAGIC, DESCRIPTOR_COUNT, MAX_PACKET_BYTES, PAYLOAD_ARENA_BYTES,
};
use uuid::Uuid;

#[test]
fn standard_layout_is_fixed_aligned_and_non_overlapping() {
    let layout = ChannelLayout::standard().unwrap();

    assert_eq!(CHANNEL_MAGIC, *b"EGRPKT01");
    // 2: wait flags in the ring header; signals only reach a waiting peer.
    assert_eq!((CHANNEL_ABI_MAJOR, CHANNEL_ABI_MINOR), (2, 0));
    assert_eq!(layout.descriptor_count(), DESCRIPTOR_COUNT);
    assert_eq!(layout.payload_arena_bytes(), PAYLOAD_ARENA_BYTES);
    assert_eq!(layout.max_packet_bytes(), MAX_PACKET_BYTES);
    assert_eq!(align_of::<ChannelHeader>(), 64);
    assert_eq!(align_of::<RingHeader>(), 64);
    assert_eq!(size_of::<RingHeader>(), 64);
    assert_eq!(size_of::<PacketDescriptor>(), 24);
    assert_eq!(layout.rx_ring_header_offset() % 64, 0);
    assert_eq!(layout.tx_ring_header_offset() % 64, 0);
    assert!(layout.rx_payload_end() <= layout.tx_ring_header_offset());
    assert!(layout.tx_payload_end() <= layout.mapping_len());
}

#[test]
fn checked_layout_rejects_invalid_capacities() {
    assert!(ChannelLayout::new(0, 1024, 512).is_err());
    assert!(ChannelLayout::new(3, 1024, 512).is_err());
    assert!(ChannelLayout::new(4, 7, 8).is_err());
    assert!(ChannelLayout::new(4, 1024, 65_536).is_err());
}

#[test]
fn external_mapping_binding_validates_before_ring_access() {
    let layout = ChannelLayout::new(4, 1024, 512).unwrap();
    let mut words = vec![0_u64; layout.mapping_len().div_ceil(8) + 8];
    let base = words.as_mut_ptr().cast::<u8>();
    let aligned = ((base as usize + 63) & !63) as *mut u8;

    let binding = unsafe {
        ChannelBinding::initialize(aligned, layout.mapping_len(), layout, Uuid::new_v4()).unwrap()
    };
    binding.rx_ring().try_push(&[1, 2, 3]).unwrap();
    assert_eq!(binding.rx_ring().try_pop().unwrap().packet(), &[1, 2, 3]);

    unsafe { aligned.write(0) };
    assert!(unsafe { ChannelBinding::from_raw(aligned, layout.mapping_len()) }.is_err());
}
