use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use egrio_platform_windows::{RawPacketSend, WindowsRawPacketSession};

use crate::shared_memory::{ChannelBinding, RingError};

pub trait PacketPumpSignals: Send + Sync + std::fmt::Debug {
    fn wait_rx_source(&self) -> Result<(), String>;
    fn wait_rx_space(&self) -> Result<(), String>;
    fn wait_tx_data(&self) -> Result<(), String>;
    /// Waits for TX data at most [`NUDGE_DELAY`]; `true` when data arrived.
    fn wait_tx_data_or_nudge(&self) -> Result<bool, String>;
    fn wait_tx_send_space(&self) -> Result<(), String>;
    fn signal_rx_data(&self) -> Result<(), String>;
    fn signal_tx_space(&self) -> Result<(), String>;
    fn cancelled(&self) -> bool;
    fn cancel(&self) -> Result<(), String>;
}

/// How long the writer, after the TX ring drained, waits for more packets
/// before nudging the raw session's reader (see
/// [`WindowsRawPacketSession::nudge_reader`]).
pub const NUDGE_DELAY: std::time::Duration = std::time::Duration::from_millis(1);

/// Called once, with the worker's error, when a worker stops on a fault
/// rather than on `stop`: the tunnel no longer carries packets.
pub type PacketPumpFault = Box<dyn Fn(&str) + Send + Sync>;

#[derive(Debug)]
pub struct PacketPump {
    signals: Arc<dyn PacketPumpSignals>,
    fault: Arc<FaultReport>,
    rx: Option<JoinHandle<Result<(), String>>>,
    tx: Option<JoinHandle<Result<(), String>>>,
}

struct FaultReport {
    faulted: AtomicBool,
    report: PacketPumpFault,
}

impl FaultReport {
    fn raise(&self, outcome: &Result<(), String>) {
        if let Err(error) = outcome {
            if !self.faulted.swap(true, Ordering::AcqRel) {
                (self.report)(error);
            }
        }
    }
}

impl std::fmt::Debug for FaultReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FaultReport")
            .field("faulted", &self.faulted)
            .finish_non_exhaustive()
    }
}

impl PacketPump {
    /// Start the service-side raw-session ↔ shared-ring bridge.
    ///
    /// # Safety
    /// The mapping behind `channel` must remain valid until `stop` has joined
    /// both workers. RX and TX ownership must remain SPSC for that duration.
    ///
    /// The session is shared (`&self`) between the two workers with no lock:
    /// the reader owns the receive direction and the writer owns the send
    /// direction, and Wintun's send/receive primitives are each documented
    /// thread-safe for exactly this single-reader/single-writer split.
    pub unsafe fn start(
        session: Box<dyn WindowsRawPacketSession>,
        channel: ChannelBinding,
        signals: Arc<dyn PacketPumpSignals>,
        fault: PacketPumpFault,
    ) -> Self {
        let fault = Arc::new(FaultReport {
            faulted: AtomicBool::new(false),
            report: fault,
        });
        let session: SharedSession = Arc::from(session);
        let rx_session = session.clone();
        let rx_signals = signals.clone();
        let rx_fault = fault.clone();
        let rx_channel = channel;
        let rx = std::thread::spawn(move || {
            // A worker parked in a wait when `stop` cancels returns a
            // `Cancelled` ring error, not `Ok`; that is the normal stop path,
            // so any error observed after cancellation is swallowed. A real
            // fault (no cancel in flight) is reported and still propagates.
            let outcome = rx_worker(&rx_session, &rx_signals, &rx_channel);
            if rx_signals.cancelled() {
                Ok(())
            } else {
                rx_fault.raise(&outcome);
                outcome
            }
        });

        let tx_session = session;
        let tx_signals = signals.clone();
        let tx_fault = fault.clone();
        let tx_channel = channel;
        let tx = std::thread::spawn(move || {
            let outcome = tx_worker(&tx_session, &tx_signals, &tx_channel);
            if tx_signals.cancelled() {
                Ok(())
            } else {
                tx_fault.raise(&outcome);
                outcome
            }
        });

        Self {
            signals,
            fault,
            rx: Some(rx),
            tx: Some(tx),
        }
    }

    /// Whether a worker stopped on a fault.
    pub fn faulted(&self) -> bool {
        self.fault.faulted.load(Ordering::Acquire)
    }

    /// Stops and joins both workers. A fault was reported when it happened;
    /// the pump it stopped is stopped all the same.
    pub fn stop(mut self) -> Result<(), String> {
        self.signals.cancel()?;
        let rx = join(self.rx.take());
        let tx = join(self.tx.take());
        if self.faulted() {
            return Ok(());
        }
        match (rx, tx) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(rx), Err(tx)) => Err(format!("RX worker: {rx}; TX worker: {tx}")),
        }
    }
}

type SharedSession = Arc<dyn WindowsRawPacketSession>;

fn rx_worker(
    session: &SharedSession,
    signals: &Arc<dyn PacketPumpSignals>,
    channel: &ChannelBinding,
) -> Result<(), String> {
    // Each packet goes from Wintun's receive ring straight into the shared
    // ring; Wintun keeps it until the push returns.
    let mut deliver = |packet: &[u8]| {
        channel
            .rx_ring()
            .push_until(
                packet,
                || signals.wait_rx_space().map_err(|_| RingError::Cancelled),
                || signals.signal_rx_data().map_err(|_| RingError::Cancelled),
                || signals.cancelled(),
            )
            .map_err(ring_error)
    };
    loop {
        if signals.cancelled() {
            return Ok(());
        }
        if !session.receive_with(&mut deliver)? {
            signals.wait_rx_source()?;
        }
    }
}

fn tx_worker(
    session: &SharedSession,
    signals: &Arc<dyn PacketPumpSignals>,
    channel: &ChannelBinding,
) -> Result<(), String> {
    // Whether packets went out since the reader was last nudged.
    let mut nudge_due = false;
    loop {
        if signals.cancelled() {
            return Ok(());
        }
        let ring = channel.tx_ring();
        let pending = match ring.try_peek() {
            Ok(packet) => packet,
            Err(RingError::WouldBlock) => {
                if ring.begin_consumer_wait() {
                    if !nudge_due {
                        signals.wait_tx_data()?;
                    } else if !signals.wait_tx_data_or_nudge()? {
                        // A full ring means the reader is busy anyway.
                        session.nudge_reader()?;
                        nudge_due = false;
                    }
                }
                continue;
            }
            Err(error) => return Err(ring_error(error)),
        };
        // Copied straight from the shared ring into Wintun's send ring.
        let sent = session.try_send_with(pending.len(), &mut |packet| {
            ring.copy_peeked(&pending, packet);
        })?;
        match sent {
            RawPacketSend::Sent => {
                ring.commit_peek(&pending).map_err(ring_error)?;
                nudge_due = true;
                if ring.producer_needs_wake() {
                    signals.signal_tx_space()?;
                }
            }
            RawPacketSend::Backpressured => signals.wait_tx_send_space()?,
        }
    }
}

fn join(worker: Option<JoinHandle<Result<(), String>>>) -> Result<(), String> {
    worker
        .expect("packet pump worker")
        .join()
        .map_err(|_| "packet pump worker panicked".to_string())?
}

fn ring_error(error: RingError) -> String {
    format!("shared packet ring failed: {error:?}")
}
