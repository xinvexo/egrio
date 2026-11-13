use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Waker};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::udprelay::{
    crypto_io::{decrypt_server_payload, encrypt_client_payload},
    options::UdpSocketControlData,
};
use tokio::net::UdpSocket;

use super::replay::ReplayWindow;
use super::{from_address, to_address, Config};
use crate::outbound::{
    recv_datagram, DatagramCodec, DatagramError, DatagramFuture, DatagramSendCancellation,
    OutboundDatagramReceiver, OutboundDatagramSender, OutboundDatagramTransport, PumpDatagrams,
    PumpFrom, PumpTo,
};
use crate::target::{parse_connect_authority, ConnectTarget};

// Retain associations for longer than SIP022's 60-second minimum, including
// old server sessions following a restart. Refuse new sessions at the bound;
// never evict a live replay window to accommodate an incoming session ID.
pub(super) const SESSION_TTL: Duration = Duration::from_secs(120);
const MAX_SERVER_SESSIONS: usize = 128;

pub(in crate::protocols::shadowsocks) fn client_transport(
    socket: Arc<UdpSocket>,
    config: Arc<Config>,
) -> OutboundDatagramTransport {
    let io = Arc::new(ClientUdpIo {
        socket,
        codec: ClientCodec::new(config),
        pump: OnceLock::new(),
    });
    OutboundDatagramTransport {
        sender: Box::new(Sender(Arc::clone(&io))),
        receiver: Box::new(Receiver(io)),
    }
}

struct ServerReplay {
    window: ReplayWindow,
    last_seen: Instant,
}

/// The packets of one Shadowsocks 2022 association: the client session
/// every packet carries, the packet counter, and the replay window of each
/// server session that answered.
pub(in crate::protocols::shadowsocks) struct ClientCodec {
    config: Arc<Config>,
    client_id: u64,
    next_packet: AtomicU64,
    sessions: Mutex<HashMap<u64, ServerReplay>>,
}

/// The proxy socket of one Shadowsocks 2022 association. The session actor
/// sends and reads through it, and once a captured flow's association is
/// learned, the packet pump does so itself.
struct ClientUdpIo {
    socket: Arc<UdpSocket>,
    codec: ClientCodec,
    /// Set once the packet pump reads the socket (see
    /// [`PumpDatagrams::hand_reads_to`]).
    pump: OnceLock<Waker>,
}

impl ClientCodec {
    /// A new association's: a client session of its own.
    pub(in crate::protocols::shadowsocks) fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            client_id: rand::random(),
            next_packet: AtomicU64::new(0),
            sessions: Mutex::new(HashMap::new()),
        }
    }

    fn seal_to(&self, address: &Address, payload: &[u8]) -> Result<BytesMut, String> {
        let packet_id = self
            .next_packet
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| "Shadowsocks 2022 UDP packet counter exhausted".to_string())?;
        let mut control = UdpSocketControlData::default();
        control.client_session_id = self.client_id;
        control.packet_id = packet_id;
        let mut packet = BytesMut::new();
        encrypt_client_payload(
            &self.config.context,
            self.config.server.method(),
            self.config.server.key(),
            address,
            &control,
            self.config.server.identity_keys(),
            payload,
            &mut packet,
        );
        Ok(packet)
    }

    /// Opens a response in place: the address it names and the length of
    /// the payload now at the start of `datagram`.
    fn open_in_place(&self, datagram: &mut [u8]) -> Result<(Address, usize), String> {
        let (size, address, control) = decrypt_server_payload(
            &self.config.context,
            self.config.server.method(),
            self.config.server.key(),
            datagram,
        )
        .map_err(|error| error.to_string())?;
        let control = control.ok_or("missing Shadowsocks 2022 UDP control data")?;
        if control.client_session_id != self.client_id {
            return Err("Shadowsocks 2022 UDP response belongs to another client session".into());
        }
        let now = Instant::now();
        let mut sessions = self.sessions.lock().expect("Shadowsocks 2022 UDP sessions");
        sessions.retain(|_, session| now.duration_since(session.last_seen) < SESSION_TTL);
        if !sessions.contains_key(&control.server_session_id)
            && sessions.len() >= MAX_SERVER_SESSIONS
        {
            return Err("Shadowsocks 2022 UDP server session limit reached".into());
        }
        let session = sessions
            .entry(control.server_session_id)
            .or_insert_with(|| ServerReplay {
                window: ReplayWindow::default(),
                last_seen: now,
            });
        if !session.window.accept(control.packet_id) {
            return Err("replayed Shadowsocks 2022 UDP response".into());
        }
        session.last_seen = now;
        Ok((address, size))
    }
}

/// A chained node's packets, the same as on a socket of this host.
impl DatagramCodec for ClientCodec {
    fn seal(&self, target: &ConnectTarget, payload: &[u8]) -> Result<Vec<u8>, DatagramError> {
        Ok(self.seal_to(&to_address(target)?, payload)?.to_vec())
    }

    /// A malformed, replayed or cross-session packet is skipped and leaves
    /// the replay windows as they were.
    fn open(&self, packet: &mut [u8]) -> Option<(ConnectTarget, Vec<u8>)> {
        let (from, size) = self.open_in_place(packet).ok()?;
        Some((from_address(from), packet[..size].to_vec()))
    }
}

impl ClientUdpIo {
    /// Asks for the next packet to wake the pump; whether one is waiting
    /// already, in which case no wakeup is registered.
    fn arm(&self) -> bool {
        self.pump.get().is_some_and(|waker| {
            self.socket
                .poll_recv_ready(&mut Context::from_waker(waker))
                .is_ready()
        })
    }
}

impl PumpDatagrams for ClientUdpIo {
    fn try_send(&self, to: &PumpTo, payload: &[u8]) -> io::Result<()> {
        let address = match to {
            PumpTo::Addr(SocketAddr::V6(remote)) if remote.scope_id() != 0 => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "scoped IPv6 targets cannot be encoded for a remote proxy",
                ))
            }
            PumpTo::Addr(remote) => Address::SocketAddress(*remote),
            PumpTo::Name(authority) => parse_connect_authority(authority)
                .and_then(|target| to_address(&target))
                .map_err(io::Error::other)?,
        };
        let packet = self
            .codec
            .seal_to(&address, payload)
            .map_err(io::Error::other)?;
        // Sent at once: a new socket's readiness starts empty, so a
        // non-blocking send through the reactor would refuse it.
        socket2::SockRef::from(&*self.socket)
            .send(&packet)
            .map(drop)
    }

    fn hand_reads_to(&self, waker: Waker) {
        if self.pump.set(waker.clone()).is_ok() && self.arm() {
            waker.wake();
        }
    }

    fn try_recv(&self, buffer: &mut [u8]) -> io::Result<(usize, PumpFrom, usize)> {
        loop {
            let read = match self.socket.try_recv(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if self.arm() {
                        continue;
                    }
                    return Err(error);
                }
                read => read?,
            };
            // A malformed, replayed or cross-session datagram is skipped like
            // a lost one, and leaves the replay windows as they were.
            let Ok((from, size)) = self.codec.open_in_place(&mut buffer[..read]) else {
                continue;
            };
            let from = match from {
                Address::SocketAddress(remote) => PumpFrom::Addr(remote),
                Address::DomainNameAddress(host, port) => {
                    PumpFrom::from_target(ConnectTarget { host, port })
                }
            };
            return Ok((size, from, size));
        }
    }
}

struct Sender(Arc<ClientUdpIo>);

impl OutboundDatagramSender for Sender {
    fn send_cancellation(&self) -> DatagramSendCancellation {
        DatagramSendCancellation::AtomicDatagram
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            let packet = self.0.codec.seal_to(&to_address(target)?, payload)?;
            self.0
                .socket
                .send(&packet)
                .await
                .map(|_| ())
                .map_err(DatagramError::NativeSocket)
        })
    }
}

struct Receiver(Arc<ClientUdpIo>);

impl OutboundDatagramReceiver for Receiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            loop {
                let (mut buffer, read) = recv_datagram(&self.0.socket)
                    .await
                    .map_err(DatagramError::NativeSocket)?;
                // A malformed, replayed or cross-session datagram cannot
                // destroy a live UDP flow or mutate its valid replay window.
                if let Ok((from, size)) = self.0.codec.open_in_place(&mut buffer[..read]) {
                    return Ok(Some((from_address(from), buffer[..size].to_vec())));
                }
            }
        })
    }

    fn pump_datagrams(&self) -> Option<Arc<dyn PumpDatagrams>> {
        Some(Arc::clone(&self.0) as Arc<dyn PumpDatagrams>)
    }
}
