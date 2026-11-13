use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use egrio_core::{PacketDevice, PacketInterest, PacketReady, PacketSend, ReceivedPacket};
use egrio_platform_windows::{RawWaitHandle, WindowsRawPacketSession};
use tokio::sync::Notify;
use uuid::Uuid;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateWaitableTimerExW, RegisterWaitForSingleObject, SetEvent, SetWaitableTimer,
    UnregisterWaitEx, WaitForMultipleObjects, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, INFINITE,
    TIMER_ALL_ACCESS, WT_EXECUTEINWAITTHREAD, WT_EXECUTEONLYONCE,
};

use crate::packet_pump::{PacketPump, PacketPumpFault, PacketPumpSignals, NUDGE_DELAY};
use crate::shared_memory::{ChannelLayout, RingError};

use super::handles::{
    duplicate_for_current_process, DuplicatedPacketHandles, MappedPacketChannel,
    PacketKernelObjects,
};
use super::identity::OwnedHandle;

/// The desktop end of the shared packet rings. Ring operations never block;
/// readiness comes from the service's RX-data and TX-space events, waited on
/// only while the Core pump is parked on that interest.
#[derive(Debug)]
pub struct RemoteWindowsPacketDevice {
    name: String,
    channel: MappedPacketChannel,
    /// Keeps the duplicated file-mapping handle alive for the view's lifetime.
    _mapping: OwnedHandle,
    rx_space: OwnedHandle,
    tx_data: OwnedHandle,
    readable: RingEventWait,
    writable: RingEventWait,
}

/// A one-shot thread-pool wait on one auto-reset ring event, armed only when
/// the pump parks; the service signals the event only while the ring's wait
/// flag is up. A fired wait leaves a `Notify` permit, so a park whose future
/// lost a select to another branch is not lost either.
#[derive(Debug)]
struct RingEventWait {
    /// Released before `event` closes and `shared` drops (field order).
    registration: Option<WaitRegistration>,
    event: OwnedHandle,
    shared: Arc<RingEventShared>,
}

#[derive(Debug, Default)]
struct RingEventShared {
    notify: Notify,
    fired: AtomicBool,
}

impl RingEventWait {
    fn new(event: OwnedHandle) -> Self {
        Self {
            registration: None,
            event,
            shared: Arc::default(),
        }
    }

    /// Ensures a wait is pending, reusing one that has not fired yet.
    fn arm(&mut self) -> Result<(), String> {
        if self.registration.is_some() && !self.shared.fired.load(Ordering::Acquire) {
            return Ok(());
        }
        // Even a fired one-shot wait must be unregistered before re-arming.
        self.registration = None;
        self.shared.fired.store(false, Ordering::Release);
        let mut wait = null_mut();
        let armed = unsafe {
            RegisterWaitForSingleObject(
                &mut wait,
                self.event.raw(),
                Some(ring_event_fired),
                Arc::as_ptr(&self.shared).cast(),
                INFINITE,
                WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD,
            )
        };
        if armed == 0 {
            return Err(format!("arm packet ring wait: {}", last_error()));
        }
        self.registration = Some(WaitRegistration(wait));
        Ok(())
    }
}

unsafe extern "system" fn ring_event_fired(context: *mut c_void, _timed_out: bool) {
    // SAFETY: `context` points into the `Arc` owned by the `RingEventWait`
    // whose registration is released, waiting for this callback, before that
    // `Arc` drops.
    let shared = unsafe { &*context.cast::<RingEventShared>() };
    shared.fired.store(true, Ordering::Release);
    shared.notify.notify_one();
}

#[derive(Debug)]
struct WaitRegistration(HANDLE);

// SAFETY: a registered wait handle may be released from any thread.
unsafe impl Send for WaitRegistration {}

impl Drop for WaitRegistration {
    fn drop(&mut self) {
        // INVALID_HANDLE_VALUE returns only after a running callback finishes.
        unsafe { UnregisterWaitEx(self.0, INVALID_HANDLE_VALUE) };
    }
}

#[derive(Debug)]
pub struct WindowsPacketSession {
    interface_index: u32,
    objects: PacketKernelObjects,
    pump: Option<PacketPump>,
}

impl WindowsPacketSession {
    /// Starts the pump between the Wintun session and the shared rings;
    /// `fault` is called if it stops carrying packets on its own.
    pub fn open(
        session: Box<dyn WindowsRawPacketSession>,
        fault: PacketPumpFault,
    ) -> Result<Self, String> {
        let interface_index = session.interface_index();
        let read_wait = session.read_wait_handle()?;
        let layout = ChannelLayout::standard().map_err(|error| format!("{error:?}"))?;
        let objects = PacketKernelObjects::new(layout, Uuid::new_v4())?;
        let signals = Arc::new(WindowsPacketPumpSignals::new(&objects, read_wait)?);
        let binding = objects.channel().binding();
        let pump = unsafe { PacketPump::start(session, binding, signals, fault) };
        Ok(Self {
            interface_index,
            objects,
            pump: Some(pump),
        })
    }

    pub const fn interface_index(&self) -> u32 {
        self.interface_index
    }

    /// Whether the tunnel carries packets: the pump runs and has not
    /// faulted.
    pub fn carries_packets(&self) -> bool {
        self.pump.as_ref().is_some_and(|pump| !pump.faulted())
    }

    pub fn duplicate_into(
        &self,
        target_process: &OwnedHandle,
    ) -> Result<DuplicatedPacketHandles, String> {
        self.objects.duplicate_into(target_process)
    }

    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(pump) = self.pump.take() {
            pump.stop()?;
        }
        Ok(())
    }
}

impl Drop for WindowsPacketSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// How long the writer waits before retrying a full Wintun send ring, in
/// 100 ns units: 1 ms.
const SEND_RETRY_100NS: i64 = 10_000;

#[derive(Debug)]
struct WindowsPacketPumpSignals {
    rx_source: OwnedHandle,
    rx_data: OwnedHandle,
    rx_space: OwnedHandle,
    tx_data: OwnedHandle,
    tx_space: OwnedHandle,
    /// The writer's timer: it retries a full Wintun send ring, which signals
    /// no free space, and bounds the wait before nudging the reader. A
    /// high-resolution waitable timer fires on time without the service
    /// raising its timer resolution: since Windows 10 2004 a 1 ms wait in a
    /// process that never called `timeBeginPeriod` lasts a whole default
    /// timer period, about 15.6 ms. A stale signal only shortens one wait.
    writer_timer: OwnedHandle,
    cancelled: OwnedHandle,
}

impl WindowsPacketPumpSignals {
    fn new(objects: &PacketKernelObjects, read_wait: RawWaitHandle) -> Result<Self, String> {
        let read_wait = usize::try_from(read_wait.get())
            .map_err(|_| "Wintun read wait handle does not fit usize".to_string())?;
        Ok(Self {
            rx_source: duplicate_for_current_process(read_wait as HANDLE)?,
            rx_data: duplicate_for_current_process(objects.rx_data_handle())?,
            rx_space: duplicate_for_current_process(objects.rx_space_handle())?,
            tx_data: duplicate_for_current_process(objects.tx_data_handle())?,
            tx_space: duplicate_for_current_process(objects.tx_space_handle())?,
            writer_timer: OwnedHandle::from_raw(unsafe {
                CreateWaitableTimerExW(
                    null(),
                    null(),
                    CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                    TIMER_ALL_ACCESS,
                )
            })?,
            cancelled: OwnedHandle::from_raw(unsafe { CreateEventW(null(), 1, 0, null()) })?,
        })
    }
}

impl WindowsPacketPumpSignals {
    /// Arms the writer's timer `delay_100ns` from now.
    fn arm_writer_timer(&self, delay_100ns: i64) -> Result<(), String> {
        // A negative due time is relative.
        let due = -delay_100ns;
        if unsafe { SetWaitableTimer(self.writer_timer.raw(), &due, 0, None, null(), 0) } == 0 {
            return Err(last_error());
        }
        Ok(())
    }
}

impl PacketPumpSignals for WindowsPacketPumpSignals {
    fn wait_rx_source(&self) -> Result<(), String> {
        wait_for(self.rx_source.raw(), self.cancelled.raw()).map_err(ring_error)
    }

    fn wait_rx_space(&self) -> Result<(), String> {
        wait_for(self.rx_space.raw(), self.cancelled.raw()).map_err(ring_error)
    }

    fn wait_tx_data(&self) -> Result<(), String> {
        wait_for(self.tx_data.raw(), self.cancelled.raw()).map_err(ring_error)
    }

    fn wait_tx_data_or_nudge(&self) -> Result<bool, String> {
        self.arm_writer_timer(NUDGE_DELAY.as_nanos() as i64 / 100)?;
        let handles = [
            self.cancelled.raw(),
            self.tx_data.raw(),
            self.writer_timer.raw(),
        ];
        match unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, INFINITE) } {
            WAIT_OBJECT_0 => Err(ring_error(RingError::Cancelled)),
            value if value == WAIT_OBJECT_0 + 1 => Ok(true),
            value if value == WAIT_OBJECT_0 + 2 => Ok(false),
            _ => Err(last_error()),
        }
    }

    fn wait_tx_send_space(&self) -> Result<(), String> {
        self.arm_writer_timer(SEND_RETRY_100NS)?;
        wait_for(self.writer_timer.raw(), self.cancelled.raw()).map_err(ring_error)
    }

    fn signal_rx_data(&self) -> Result<(), String> {
        signal(self.rx_data.raw())
    }

    fn signal_tx_space(&self) -> Result<(), String> {
        signal(self.tx_space.raw())
    }

    fn cancelled(&self) -> bool {
        is_signaled(self.cancelled.raw())
    }

    fn cancel(&self) -> Result<(), String> {
        signal(self.cancelled.raw())
    }
}

impl RemoteWindowsPacketDevice {
    pub fn open(name: impl Into<String>, handles: DuplicatedPacketHandles) -> Result<Self, String> {
        let mapping = handle(handles.mapping)?;
        let rx_data = handle(handles.rx_data_available)?;
        let rx_space = handle(handles.rx_space_available)?;
        let tx_data = handle(handles.tx_data_available)?;
        let tx_space = handle(handles.tx_space_available)?;
        let len = usize::try_from(handles.mapping_len)
            .map_err(|_| "packet mapping length does not fit usize".to_string())?;
        let channel = MappedPacketChannel::open(mapping.raw(), len)?;
        if channel.binding().channel_id() != handles.channel_id {
            return Err("packet channel UUID does not match control response".into());
        }
        Ok(Self {
            name: name.into(),
            channel,
            _mapping: mapping,
            rx_space,
            tx_data,
            readable: RingEventWait::new(rx_data),
            writable: RingEventWait::new(tx_space),
        })
    }
}

impl PacketDevice for RemoteWindowsPacketDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, String> {
        let binding = self.channel.binding();
        let ring = binding.rx_ring();
        let popped = match ring.try_pop() {
            Ok(popped) => popped,
            Err(RingError::WouldBlock) => return Ok(None),
            Err(error) => return Err(ring_error(error)),
        };
        if ring.producer_needs_wake() {
            signal(self.rx_space.raw())?;
        }
        Ok(Some(popped.packet.into()))
    }

    fn try_send(&mut self, packet: &[u8]) -> Result<PacketSend, String> {
        self.try_send_parts(&[packet])
    }

    fn try_send_parts(&mut self, parts: &[&[u8]]) -> Result<PacketSend, String> {
        let binding = self.channel.binding();
        let ring = binding.tx_ring();
        match ring.try_push_parts(parts) {
            Ok(()) => {
                if ring.consumer_needs_wake() {
                    signal(self.tx_data.raw())?;
                }
                Ok(PacketSend::Sent)
            }
            Err(RingError::WouldBlock) => Ok(PacketSend::Full),
            Err(error) => Err(ring_error(error)),
        }
    }

    fn ready(&mut self, interest: PacketInterest) -> PacketReady<'_> {
        // Raise the wait flags first: a ring that changed meanwhile is ready
        // now, and otherwise the service signals once it sees the flag.
        let binding = self.channel.binding();
        let readable_now = interest.read && !binding.rx_ring().begin_consumer_wait();
        let writable_now = interest.write && !binding.tx_ring().begin_producer_wait();
        if readable_now || writable_now {
            return Box::pin(std::future::ready(Ok(())));
        }
        let armed = (|| -> Result<(), String> {
            if interest.read {
                self.readable.arm()?;
            }
            if interest.write {
                self.writable.arm()?;
            }
            Ok(())
        })();
        let readable = Arc::clone(&self.readable.shared);
        let writable = Arc::clone(&self.writable.shared);
        Box::pin(async move {
            armed?;
            tokio::select! {
                () = readable.notify.notified(), if interest.read => {}
                () = writable.notify.notified(), if interest.write => {}
                () = std::future::pending(), if !interest.read && !interest.write => {}
            }
            Ok(())
        })
    }
}

fn handle(value: u64) -> Result<OwnedHandle, String> {
    let value =
        usize::try_from(value).map_err(|_| "packet handle does not fit usize".to_string())?;
    OwnedHandle::from_raw(value as HANDLE)
}

fn signal(handle: HANDLE) -> Result<(), String> {
    if unsafe { SetEvent(handle) } == 0 {
        Err(last_error())
    } else {
        Ok(())
    }
}

fn wait_for(event: HANDLE, cancelled: HANDLE) -> Result<(), RingError> {
    let handles = [cancelled, event];
    match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) } {
        WAIT_OBJECT_0 => Err(RingError::Cancelled),
        value if value == WAIT_OBJECT_0 + 1 => Ok(()),
        _ => Err(RingError::CorruptState),
    }
}

fn is_signaled(event: HANDLE) -> bool {
    (unsafe { WaitForMultipleObjects(1, &event, 0, 0) }) == WAIT_OBJECT_0
}

fn ring_error(error: RingError) -> String {
    format!("shared packet ring failed: {error:?}")
}

fn last_error() -> String {
    std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32).to_string()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_DUP_HANDLE,
    };

    use super::*;

    fn device_pair() -> (PacketKernelObjects, RemoteWindowsPacketDevice) {
        let objects =
            PacketKernelObjects::new(ChannelLayout::new(2, 64, 64).unwrap(), Uuid::from_u128(9))
                .unwrap();
        let this_process = OwnedHandle::from_raw(unsafe {
            OpenProcess(PROCESS_DUP_HANDLE, 0, GetCurrentProcessId())
        })
        .unwrap();
        let handles = objects.duplicate_into(&this_process).unwrap();
        let device = RemoteWindowsPacketDevice::open("test-ring", handles).unwrap();
        (objects, device)
    }

    const READ: PacketInterest = PacketInterest {
        read: true,
        write: false,
    };
    const WRITE: PacketInterest = PacketInterest {
        read: false,
        write: true,
    };

    #[tokio::test]
    async fn service_rx_signal_wakes_a_parked_reader() {
        let (objects, mut device) = device_pair();
        assert_eq!(device.try_recv().unwrap(), None);
        let binding = objects.channel().binding();
        let waiter = tokio::spawn(async move {
            device.ready(READ).await.unwrap();
            let packet = device.try_recv().unwrap();
            (device, packet)
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished(), "an empty ring parks the reader");
        binding.rx_ring().try_push(&[0x45, 1, 2]).unwrap();
        signal(objects.rx_data_handle()).unwrap();
        let (_device, packet) = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("RX event wakes the reader")
            .unwrap();
        assert_eq!(packet, Some(vec![0x45, 1, 2].into()));
    }

    #[tokio::test]
    async fn a_full_tx_ring_reports_full_without_blocking_until_space_returns() {
        let (objects, mut device) = device_pair();
        assert_eq!(device.try_send(&[1; 16]).unwrap(), PacketSend::Sent);
        assert_eq!(device.try_send(&[2; 16]).unwrap(), PacketSend::Sent);
        assert_eq!(device.try_send(&[3; 16]).unwrap(), PacketSend::Full);
        let binding = objects.channel().binding();
        let pending = binding.tx_ring().try_peek().unwrap();
        binding.tx_ring().commit_peek(&pending).unwrap();
        signal(objects.tx_space_handle()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), device.ready(WRITE))
            .await
            .expect("TX space event wakes the writer")
            .unwrap();
        assert_eq!(device.try_send(&[3; 16]).unwrap(), PacketSend::Sent);
    }

    #[tokio::test]
    async fn a_park_that_loses_its_select_keeps_the_wakeup() {
        let (objects, mut device) = device_pair();
        // The pump drops the ready future when another branch wins; the wait
        // stays armed and its signal must reach the next park.
        assert!(
            tokio::time::timeout(Duration::from_millis(20), device.ready(READ))
                .await
                .is_err()
        );
        signal(objects.rx_data_handle()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), device.ready(READ))
            .await
            .expect("the earlier armed wait delivered the signal")
            .unwrap();
    }

    #[tokio::test]
    async fn a_fired_wait_rearms_for_the_next_park() {
        let (objects, mut device) = device_pair();
        for round in 0..3 {
            signal(objects.rx_data_handle()).unwrap();
            tokio::time::timeout(Duration::from_secs(2), device.ready(READ))
                .await
                .unwrap_or_else(|_| panic!("round {round}: signal wakes the park"))
                .unwrap();
            // Consumed: without a new signal the next park stays parked.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), device.ready(READ))
                    .await
                    .is_err(),
                "round {round}: a consumed signal must not wake again"
            );
        }
    }
}
