mod abi;
mod ring;

pub use abi::{
    ChannelHeader, ChannelLayout, LayoutError, PacketDescriptor, RingHeader, CHANNEL_ABI_MAJOR,
    CHANNEL_ABI_MINOR, CHANNEL_MAGIC, DESCRIPTOR_COUNT, MAX_PACKET_BYTES, PAYLOAD_ARENA_BYTES,
};
pub use ring::{
    ChannelBinding, ChannelMemory, ChannelView, RingError, RingPeek, RingPop, RingView,
};
