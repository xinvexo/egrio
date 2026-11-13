//! DIRECT: no proxy hop, the egress runtime dials the target itself.

use crate::outbound::{DatagramError, DatagramFuture, UDP_DATAGRAM_BUFFERS};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Waker};

use tokio::net::UdpSocket;
use tokio::sync::{Notify, OnceCell};

use super::{
    write_early_data, BoxedOutboundStream, OutboundConnector, OutboundDatagramReceiver,
    OutboundDatagramSender, OutboundDatagramTransport, OutboundError, OutboundFuture,
    OutboundResultExt, OutboundStage, PumpDatagrams, PumpFrom, PumpTo,
};
use crate::egress::{EgressAddressFamily, EgressRuntime};
use crate::target::ConnectTarget;

#[derive(Debug)]
pub(crate) struct DirectConnector;

impl OutboundConnector for DirectConnector {
    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let mut stream = egress
                .connect_target_tcp(target)
                .await
                .map_err(OutboundError::target_dial)?;
            write_early_data(&mut stream, early_data)
                .await
                .at(OutboundStage::Target)?;
            Ok(Box::new(stream) as BoxedOutboundStream)
        })
    }

    fn connect_datagram<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        _target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        Box::pin(async move {
            // One endpoint-independent mapping per address family. Socket
            // creation is lazy, after resolution identifies the actual family.
            let sockets = Arc::new(DirectDatagramSockets {
                egress: egress.clone(),
                v4: OnceCell::new(),
                v6: OnceCell::new(),
                v4_coalesced: AtomicBool::new(false),
                v6_coalesced: AtomicBool::new(false),
                v4_unsegmented: AtomicBool::new(false),
                v6_unsegmented: AtomicBool::new(false),
                changed: Notify::new(),
                pump: OnceLock::new(),
            });
            Ok(OutboundDatagramTransport {
                sender: Box::new(DirectDatagramSender {
                    sockets: sockets.clone(),
                }),
                receiver: Box::new(DirectDatagramReceiver { sockets }),
            })
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn is_direct(&self) -> bool {
        true
    }
}

/// The sockets of one DIRECT association: one endpoint-independent mapping
/// per address family, created when a datagram first needs it.
struct DirectDatagramSockets {
    egress: EgressRuntime,
    v4: OnceCell<Arc<UdpSocket>>,
    v6: OnceCell<Arc<UdpSocket>>,
    /// Whether the platform coalesces what each family's socket receives
    /// (see [`Self::recv`]): only once the pump reads the sockets, since a
    /// plain read cannot tell coalesced datagrams apart.
    v4_coalesced: AtomicBool,
    v6_coalesced: AtomicBool,
    /// Set once the platform could not segment a family's sends (see
    /// [`PumpDatagrams::try_send_train`]); trains then go one datagram at a
    /// time.
    v4_unsegmented: AtomicBool,
    v6_unsegmented: AtomicBool,
    changed: Notify,
    /// Set once the packet pump reads these sockets itself (see
    /// [`Self::hand_reads_to`]): readiness wakes it, and the receiver half is
    /// no longer polled.
    pump: OnceLock<Waker>,
}

impl PumpDatagrams for DirectDatagramSockets {
    fn try_send(&self, to: &PumpTo, payload: &[u8]) -> std::io::Result<()> {
        // DIRECT resolves every name before it sends.
        let PumpTo::Addr(remote) = to else {
            return Err(std::io::ErrorKind::NotConnected.into());
        };
        match self.socket(remote.is_ipv6()) {
            Some(socket) => send_now(socket, payload, *remote).map(drop),
            None => Err(std::io::ErrorKind::NotConnected.into()),
        }
    }

    /// One segmented send where the platform has it (the datagrams a client's
    /// socket sent as one train, a QUIC upload's), else one datagram at a time.
    fn try_send_train(
        &self,
        to: &PumpTo,
        payload: &[u8],
        segment: usize,
    ) -> std::io::Result<usize> {
        let PumpTo::Addr(remote) = to else {
            return Err(std::io::ErrorKind::NotConnected.into());
        };
        let Some(socket) = self.socket(remote.is_ipv6()) else {
            return Err(std::io::ErrorKind::NotConnected.into());
        };
        let unsegmented = if remote.is_ipv6() {
            &self.v6_unsegmented
        } else {
            &self.v4_unsegmented
        };
        if !unsegmented.load(Ordering::Acquire) {
            match self
                .egress
                .send_segmented(socket, payload, segment, *remote)
            {
                Ok(sent) => return Ok(sent),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Err(error),
                Err(error) if error.kind() == std::io::ErrorKind::Unsupported => {
                    unsegmented.store(true, Ordering::Release);
                }
                // A train the route refuses to segment (a segment larger
                // than its MTU, say) still goes out datagram by datagram.
                Err(_) => {}
            }
        }
        let mut sent = 0;
        for datagram in payload.chunks(segment) {
            match send_now(socket, datagram, *remote) {
                Ok(_) => sent += 1,
                Err(error) if sent == 0 => return Err(error),
                Err(_) => break,
            }
        }
        Ok(sent)
    }

    fn hand_reads_to(&self, pump: Waker) {
        if self.pump.set(pump).is_err() {
            return;
        }
        for (ipv6, socket) in [(false, self.v4.get()), (true, self.v6.get())] {
            if let Some(socket) = socket {
                self.coalesce(socket, ipv6);
                self.wake_if_ready(socket);
            }
        }
    }

    fn try_recv(&self, buffer: &mut [u8]) -> std::io::Result<(usize, PumpFrom, usize)> {
        for (ipv6, socket) in [(false, self.v4.get()), (true, self.v6.get())] {
            let Some(socket) = socket else {
                continue;
            };
            loop {
                match self.recv(socket, ipv6, buffer) {
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if self.arm(socket) {
                            continue;
                        }
                        break;
                    }
                    other => {
                        return other.map(|(length, sender, segment)| {
                            (length, PumpFrom::Addr(sender), segment)
                        })
                    }
                }
            }
        }
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

impl DirectDatagramSockets {
    /// The family's socket, once a datagram to that family has created it.
    fn socket(&self, ipv6: bool) -> Option<&Arc<UdpSocket>> {
        if ipv6 {
            self.v6.get()
        } else {
            self.v4.get()
        }
    }

    /// Reads, without blocking, what one receive on `socket` (the family's
    /// socket of these) gives: one datagram, or where the platform coalesces,
    /// the datagrams of one sender that arrived together. The bytes read,
    /// their sender, and the size of each datagram but the last.
    fn recv(
        &self,
        socket: &UdpSocket,
        ipv6: bool,
        buffer: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, usize)> {
        if self.coalesced(ipv6).load(Ordering::Acquire) {
            socket.try_io(tokio::io::Interest::READABLE, || {
                self.egress.recv_coalesced(socket, buffer)
            })
        } else {
            socket
                .try_recv_from(buffer)
                .map(|(read, remote)| (read, remote, read))
        }
    }

    fn coalesced(&self, ipv6: bool) -> &AtomicBool {
        if ipv6 {
            &self.v6_coalesced
        } else {
            &self.v4_coalesced
        }
    }

    /// Turns on receive coalescing for the family's socket once the pump
    /// reads it.
    fn coalesce(&self, socket: &UdpSocket, ipv6: bool) {
        if self.pump.get().is_some() && self.egress.coalesce_datagrams(socket) {
            self.coalesced(ipv6).store(true, Ordering::Release);
        }
    }

    /// Asks for the next datagram on `socket` to wake the pump; whether one
    /// is waiting already, in which case no wakeup is registered.
    fn arm(&self, socket: &UdpSocket) -> bool {
        self.pump.get().is_some_and(|waker| {
            socket
                .poll_recv_ready(&mut Context::from_waker(waker))
                .is_ready()
        })
    }

    fn wake_if_ready(&self, socket: &UdpSocket) {
        if self.arm(socket) {
            if let Some(waker) = self.pump.get() {
                waker.wake_by_ref();
            }
        }
    }

    async fn for_remote(&self, remote: SocketAddr) -> Result<Arc<UdpSocket>, String> {
        let slot = if remote.is_ipv6() { &self.v6 } else { &self.v4 };
        let initializing = slot.get().is_none();
        let socket = slot
            .get_or_try_init(|| async {
                // A shared family mapping has no single remote. In particular a
                // loopback first packet must not exempt its later public traffic.
                let family = if remote.is_ipv6() {
                    EgressAddressFamily::Ipv6
                } else {
                    EgressAddressFamily::Ipv4
                };
                let socket = self
                    .egress
                    .bind_udp_for_family(family, "DIRECT UDP relay socket")
                    .await
                    .map_err(|error| error.to_string())?;
                self.coalesce(&socket, remote.is_ipv6());
                Ok::<_, String>(Arc::new(socket))
            })
            .await?
            .clone();
        if initializing {
            self.changed.notify_one();
            self.wake_if_ready(&socket);
        }
        Ok(socket)
    }
}

struct DirectDatagramSender {
    sockets: Arc<DirectDatagramSockets>,
}

impl OutboundDatagramSender for DirectDatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        crate::outbound::DatagramSendCancellation::AtomicDatagram
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            // Only the common DNS service caches addresses. Each new send
            // observes its configured purpose, policy and remaining DNS TTL.
            let remote = self
                .sockets
                .egress
                .udp_direct_addr_for_target(target)
                .await
                .map_err(DatagramError::Rejected)?;
            let socket = self
                .sockets
                .for_remote(remote)
                .await
                .map_err(DatagramError::Rejected)?;
            match send_now(&socket, payload, remote) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => socket
                    .send_to(payload, remote)
                    .await
                    .map(|_| ())
                    .map_err(DatagramError::NativeSocket),
                sent => sent.map(|_| ()).map_err(DatagramError::NativeSocket),
            }
        })
    }
}

/// Sends one datagram at once. A non-blocking UDP send fails only when the
/// socket's buffer is full, but the reactor's readiness for a new socket
/// starts empty: `try_send_to` refused the first datagrams until the
/// reactor's next turn, and `send_to` waited for it.
fn send_now(socket: &UdpSocket, payload: &[u8], remote: SocketAddr) -> std::io::Result<usize> {
    socket2::SockRef::from(socket).send_to(payload, &remote.into())
}

struct DirectDatagramReceiver {
    sockets: Arc<DirectDatagramSockets>,
}

impl OutboundDatagramReceiver for DirectDatagramReceiver {
    fn pump_datagrams(&self) -> Option<Arc<dyn PumpDatagrams>> {
        Some(Arc::clone(&self.sockets) as Arc<dyn PumpDatagrams>)
    }

    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            loop {
                // Register before reading either slot: publishing the first
                // socket or a new family cannot strand an already waiting reader.
                let changed = self.sockets.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let v4 = self.sockets.v4.get().cloned();
                let v6 = self.sockets.v6.get().cloned();
                let socket = match (v4, v6) {
                    (None, None) => {
                        changed.await;
                        continue;
                    }
                    (Some(socket), None) | (None, Some(socket)) => tokio::select! {
                        ready = socket.readable() => { ready.map_err(DatagramError::NativeSocket)?; socket },
                        _ = changed => continue,
                    },
                    (Some(v4), Some(v6)) => tokio::select! {
                        ready = v4.readable() => { ready.map_err(DatagramError::NativeSocket)?; v4 },
                        ready = v6.readable() => { ready.map_err(DatagramError::NativeSocket)?; v6 },
                        _ = changed => continue,
                    },
                };
                // Borrowed for this read only: a waiting association holds
                // no receive buffer.
                let mut buffer = UDP_DATAGRAM_BUFFERS.take();
                match socket.try_recv_from(&mut buffer) {
                    Ok((read, remote)) => {
                        return Ok(Some((
                            ConnectTarget {
                                host: match remote {
                                    SocketAddr::V6(address) if address.scope_id() != 0 => {
                                        format!("{}%{}", address.ip(), address.scope_id())
                                    }
                                    _ => remote.ip().to_string(),
                                },
                                port: remote.port(),
                            },
                            buffer[..read].to_vec(),
                        )))
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(error) => return Err(DatagramError::NativeSocket(error)),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::NativeCoreEgressConfig;
    use std::task::Poll;
    use std::time::Duration;

    /// A new association's socket has not met the reactor yet: its first
    /// datagram goes out on the actor's first poll, and the pump can send on
    /// it at once instead of dropping the datagram.
    #[tokio::test]
    async fn a_new_socket_sends_before_the_reactor_has_seen_it() {
        let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let remote = receiver.local_addr().unwrap();
        let target = ConnectTarget {
            host: remote.ip().to_string(),
            port: remote.port(),
        };
        let egress = EgressRuntime::new(NativeCoreEgressConfig::default());
        let transport = DirectConnector
            .connect_datagram(&egress, &target)
            .await
            .unwrap();
        let mut send = transport.sender.send(&target, b"one");
        let polled = send.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(
            matches!(polled, Poll::Ready(Ok(()))),
            "the first send waited for the reactor"
        );
        drop(send);
        transport
            .receiver
            .pump_datagrams()
            .unwrap()
            .try_send(&PumpTo::Addr(remote), b"two")
            .expect("the pump's send on the fresh socket");
        let mut buffer = [0; 16];
        for expected in [b"one", b"two"] {
            let (read, _) = receiver.recv_from(&mut buffer).unwrap();
            assert_eq!(&buffer[..read], expected);
        }
    }
}
