#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawPacketSend {
    Sent,
    Backpressured,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawWaitHandle(u64);

impl RawWaitHandle {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A raw L3 packet session over the capture adapter.
///
/// Every method takes `&self`: the receive and send directions are independent
/// and run concurrently on separate threads with no cross-direction lock. This
/// mirrors the underlying Wintun session, whose `WintunReceivePacket`,
/// `WintunReleaseReceivePacket`, `WintunAllocateSendPacket`, and
/// `WintunSendPacket` are each documented thread-safe, with only the
/// allocate-order-defines-send-order caveat — satisfied because a single
/// writer thread owns the send direction. Serializing the two directions
/// through one lock (as an earlier `&mut self` contract forced) let a hot
/// writer starve the reader off the lock, stalling the client's ACK stream and
/// wedging sustained downloads in retransmission backoff.
pub trait WindowsRawPacketSession: Send + Sync {
    fn adapter_name(&self) -> &str;
    fn interface_index(&self) -> u32;
    /// Hands the next received packet to `deliver` while the session still
    /// holds it, so the packet is copied once, straight to its destination.
    /// Returns `Ok(false)` without calling `deliver` when none is waiting.
    fn receive_with(
        &self,
        deliver: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<bool, String>;
    /// Allocates a `len`-byte packet in the send ring, lets `fill` write it in
    /// place and sends it. `Backpressured`, without calling `fill`, while the
    /// send ring has no room.
    fn try_send_with(
        &self,
        len: usize,
        fill: &mut dyn FnMut(&mut [u8]),
    ) -> Result<RawPacketSend, String>;
    /// Sends a packet the IP layer discards, which wakes a reader that missed
    /// the wakeup for the packets sent before it.
    fn nudge_reader(&self) -> Result<RawPacketSend, String>;
    fn read_wait_handle(&self) -> Result<RawWaitHandle, String>;
}
