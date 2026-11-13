use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egrio_platform_windows::{RawPacketSend, RawWaitHandle, WindowsRawPacketSession};
use egrio_service::packet_pump::{PacketPump, PacketPumpSignals};
use egrio_service::shared_memory::{ChannelLayout, ChannelMemory, RingError};
use uuid::Uuid;

#[derive(Debug)]
struct FakeSession {
    inbound: Arc<Mutex<VecDeque<Vec<u8>>>>,
    outbound: Arc<Mutex<Vec<Vec<u8>>>>,
    send_attempts: Arc<AtomicUsize>,
    nudges: Arc<AtomicUsize>,
}

impl WindowsRawPacketSession for FakeSession {
    fn adapter_name(&self) -> &str {
        "fake-wintun"
    }

    fn interface_index(&self) -> u32 {
        7
    }

    fn receive_with(
        &self,
        deliver: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<bool, String> {
        let Some(packet) = self.inbound.lock().unwrap().pop_front() else {
            return Ok(false);
        };
        deliver(&packet)?;
        Ok(true)
    }

    fn try_send_with(
        &self,
        len: usize,
        fill: &mut dyn FnMut(&mut [u8]),
    ) -> Result<RawPacketSend, String> {
        if self.send_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            return Ok(RawPacketSend::Backpressured);
        }
        let mut packet = vec![0; len];
        fill(&mut packet);
        self.outbound.lock().unwrap().push(packet);
        Ok(RawPacketSend::Sent)
    }

    fn nudge_reader(&self) -> Result<RawPacketSend, String> {
        self.nudges.fetch_add(1, Ordering::SeqCst);
        Ok(RawPacketSend::Sent)
    }

    fn read_wait_handle(&self) -> Result<RawWaitHandle, String> {
        Ok(RawWaitHandle::new(0))
    }
}

#[derive(Debug, Default)]
struct PollSignals {
    cancelled: AtomicBool,
}

impl PacketPumpSignals for PollSignals {
    fn wait_rx_source(&self) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
    fn wait_rx_space(&self) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
    fn wait_tx_data(&self) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
    fn wait_tx_data_or_nudge(&self) -> Result<bool, String> {
        std::thread::sleep(Duration::from_millis(1));
        Ok(false)
    }
    fn wait_tx_send_space(&self) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
    fn signal_rx_data(&self) -> Result<(), String> {
        Ok(())
    }
    fn signal_tx_space(&self) -> Result<(), String> {
        Ok(())
    }
    fn cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
    fn cancel(&self) -> Result<(), String> {
        self.cancelled.store(true, Ordering::Release);
        Ok(())
    }
}

#[test]
fn packet_pump_bridges_both_directions_and_retains_tx_during_backpressure() {
    let channel = Arc::new(
        ChannelMemory::new(
            ChannelLayout::new(8, 1024, 512).unwrap(),
            Uuid::from_u128(7),
        )
        .unwrap(),
    );
    let inbound = Arc::new(Mutex::new(VecDeque::from([vec![1, 2, 3]])));
    let outbound = Arc::new(Mutex::new(Vec::new()));
    let send_attempts = Arc::new(AtomicUsize::new(0));
    let nudges = Arc::new(AtomicUsize::new(0));
    let session = FakeSession {
        inbound,
        outbound: outbound.clone(),
        send_attempts: send_attempts.clone(),
        nudges: nudges.clone(),
    };
    let signals = Arc::new(PollSignals::default());
    let binding = channel.binding();
    let faults = Arc::new(AtomicUsize::new(0));
    let fault = {
        let faults = faults.clone();
        Box::new(move |_: &str| {
            faults.fetch_add(1, Ordering::SeqCst);
        })
    };
    let pump = unsafe { PacketPump::start(Box::new(session), binding, signals, fault) };

    let deadline = Instant::now() + Duration::from_secs(1);
    let received = loop {
        match channel.rx_ring().try_pop() {
            Ok(packet) => break packet.packet,
            Err(RingError::WouldBlock) if Instant::now() < deadline => std::thread::yield_now(),
            result => panic!("RX packet not delivered: {result:?}"),
        }
    };
    assert_eq!(received, [1, 2, 3]);

    channel.tx_ring().try_push(&[4, 5, 6]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while outbound.lock().unwrap().is_empty() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(outbound.lock().unwrap().as_slice(), &[vec![4, 5, 6]]);
    assert!(send_attempts.load(Ordering::SeqCst) >= 2);
    // The pump frees the slot only after the send it observed here.
    let deadline = Instant::now() + Duration::from_secs(1);
    while channel.tx_ring().try_peek().is_ok() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert_eq!(
        channel.tx_ring().try_peek().unwrap_err(),
        RingError::WouldBlock
    );

    // With nothing more to send, the writer nudges the reader once.
    let deadline = Instant::now() + Duration::from_secs(1);
    while nudges.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::yield_now();
    }
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(nudges.load(Ordering::SeqCst), 1);

    // Stopping is no fault.
    assert!(!pump.faulted());
    pump.stop().unwrap();
    assert_eq!(faults.load(Ordering::SeqCst), 0);
}

/// A Wintun session that ends under the pump (the adapter went away) fails
/// every receive.
#[derive(Debug)]
struct EndedSession;

impl WindowsRawPacketSession for EndedSession {
    fn adapter_name(&self) -> &str {
        "ended-wintun"
    }

    fn interface_index(&self) -> u32 {
        7
    }

    fn receive_with(
        &self,
        _deliver: &mut dyn FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<bool, String> {
        Err("Reached the end of the file. (os error 38)".into())
    }

    fn try_send_with(
        &self,
        _len: usize,
        _fill: &mut dyn FnMut(&mut [u8]),
    ) -> Result<RawPacketSend, String> {
        Err("Reached the end of the file. (os error 38)".into())
    }

    fn nudge_reader(&self) -> Result<RawPacketSend, String> {
        Ok(RawPacketSend::Sent)
    }

    fn read_wait_handle(&self) -> Result<RawWaitHandle, String> {
        Ok(RawWaitHandle::new(0))
    }
}

#[test]
fn a_pump_whose_session_ends_reports_one_fault() {
    let channel = Arc::new(
        ChannelMemory::new(
            ChannelLayout::new(8, 1024, 512).unwrap(),
            Uuid::from_u128(8),
        )
        .unwrap(),
    );
    let faults = Arc::new(Mutex::new(Vec::new()));
    let fault = {
        let faults = faults.clone();
        Box::new(move |error: &str| faults.lock().unwrap().push(error.to_string()))
    };
    let signals = Arc::new(PollSignals::default());
    let pump =
        unsafe { PacketPump::start(Box::new(EndedSession), channel.binding(), signals, fault) };
    // The writer fails too once it has a packet to send.
    channel.tx_ring().try_push(&[4, 5, 6]).unwrap();

    let deadline = Instant::now() + Duration::from_secs(1);
    while !pump.faulted() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(pump.faulted());
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(
        faults.lock().unwrap().as_slice(),
        ["Reached the end of the file. (os error 38)"],
        "reported once, with the error"
    );
    // The fault is reported; stopping the pump it stopped succeeds.
    pump.stop().unwrap();
}
