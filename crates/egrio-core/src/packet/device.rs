//! The platform packet-device contract driven by the Core packet pump.
//!
//! A device moves whole IP packets between the OS capture interface and the
//! pump. Every operation is non-blocking; [`PacketDevice::ready`] is the only
//! wait, so the pump sleeps on real readiness instead of polling and a stop
//! request can cancel it at any point.
use std::fmt;
use std::future::Future;
use std::pin::Pin;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketSend {
    Sent,
    /// The device cannot take the packet now; the pump keeps it and waits
    /// for write readiness, backpressuring its producers.
    Full,
}

/// Which of a capture's queues a pump serves. A capture can read through
/// several queues (a Linux multi-queue TUN), the kernel keeping each flow on
/// one of them; each queue's pump runs the TCP engine of the flows that arrive
/// on it and takes the replies of the UDP flows its datagrams opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketQueue {
    pub index: usize,
    pub count: usize,
}

impl PacketQueue {
    /// The one queue of a capture that has one.
    pub const ONLY: Self = Self { index: 0, count: 1 };
}

/// The runtime each capture queue's pump runs on, so a flow whose work is
/// bound to a runtime (a connection all of an outbound's flows share) can be
/// given to the queue on the same thread.
#[derive(Debug, Default, Clone)]
pub(crate) struct PumpRuntimes(std::sync::Arc<std::sync::Mutex<Vec<Option<tokio::runtime::Id>>>>);

impl PumpRuntimes {
    /// Records that `queue`'s pump runs on `runtime`; a capture with another
    /// queue count replaces the record.
    pub(crate) fn register(&self, queue: PacketQueue, runtime: tokio::runtime::Id) {
        let mut runtimes = self.0.lock().expect("pump runtimes");
        if runtimes.len() != queue.count {
            runtimes.clear();
            runtimes.resize(queue.count, None);
        }
        if let Some(slot) = runtimes.get_mut(queue.index) {
            *slot = Some(runtime);
        }
    }

    /// The queue whose pump runs on `runtime`, if one does.
    pub(crate) fn queue_of(&self, runtime: tokio::runtime::Id) -> Option<usize> {
        self.0
            .lock()
            .expect("pump runtimes")
            .iter()
            .position(|registered| *registered == Some(runtime))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketInterest {
    pub read: bool,
    pub write: bool,
}

pub type PacketReady<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// What one [`PacketDevice::try_recv`] hands over: an IP packet, or the UDP
/// datagrams one socket sent together (a Linux TUN's `GSO_UDP_L4` frame) as
/// one IP packet whose IP and UDP lengths cover them all.
///
/// The bytes are a `Vec` the device allocates for each packet -- at a
/// 1500-byte MTU, one allocation per 1.5 KB captured -- and the TCP engine
/// keeps slices of it, so it lives until the receive side has passed its
/// payload on. A pool returned through `Bytes::from_owner` still needs an
/// owner allocation; slicing a shared block pins that block until every
/// retained packet slice is released. The owned vector keeps this lifetime
/// contract explicit across platforms. Use `e2e_packet_throughput` to assess
/// allocation and copying changes on the target platform.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedPacket {
    pub bytes: Vec<u8>,
    /// For a train: each datagram's payload bytes, the last one fewer. Its
    /// UDP checksum field is not a checksum of the train.
    pub udp_segment: Option<usize>,
}

impl From<Vec<u8>> for ReceivedPacket {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            udp_segment: None,
        }
    }
}

pub trait PacketDevice: Send + fmt::Debug {
    fn name(&self) -> &str;

    /// Returns one whole IP packet or train of UDP datagrams, or `None` when
    /// none is available now. An error means the device is gone and ends the
    /// pump.
    fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, String>;

    /// Queues one whole IP packet toward the OS. An error is scoped to this
    /// packet; a dead device surfaces through `try_recv`.
    fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String>;

    /// Whether the OS finishes the TCP checksums of the segments this device
    /// is given by [`PacketDevice::try_send_parts`]: those then arrive with
    /// the checksum field holding only the pseudo-header sum, and the device
    /// tells the OS where the checksum starts and goes (the Linux TUN's
    /// virtio-net header). Otherwise the pump completes them first.
    fn completes_tcp_checksums(&self) -> bool {
        false
    }

    /// Queues one TCP segment of the TCP stack as consecutive parts: its
    /// header and slices of the relay's buffers. Devices that write a file
    /// descriptor gather the parts in one `writev`; the default joins them
    /// first.
    fn try_send_parts(&mut self, parts: &[&[u8]]) -> Result<PacketSend, String> {
        let mut packet = Vec::with_capacity(parts.iter().map(|part| part.len()).sum());
        for part in parts {
            packet.extend_from_slice(part);
        }
        self.try_send(&packet)
    }

    /// Whether the device takes a train of UDP datagrams as one frame
    /// ([`PacketDevice::try_send_udp_train`]), which its OS cuts into the
    /// datagrams; otherwise the pump writes each datagram.
    fn sends_udp_trains(&self) -> bool {
        false
    }

    /// Queues `payload` as datagrams of `segment` bytes each, the last one
    /// shorter, behind copies of `header`: one IP and UDP header whose
    /// lengths cover the whole train and whose UDP checksum field holds the
    /// pseudo-header sum. Called only when the device
    /// [sends UDP trains](PacketDevice::sends_udp_trains).
    fn try_send_udp_train(
        &mut self,
        header: &[u8],
        payload: &[u8],
        segment: usize,
    ) -> Result<PacketSend, String> {
        let _ = (header, payload, segment);
        Err(format!("{} takes no UDP trains", self.name()))
    }

    /// Resolves when `try_recv` (for `read`) or `try_send` after `Full` (for
    /// `write`) may make progress. Devices with internally buffered output
    /// flush it while waiting. Spurious wakeups are allowed; the future must
    /// be cancel-safe because the pump selects it against other events.
    fn ready(&mut self, interest: PacketInterest) -> PacketReady<'_>;
}
