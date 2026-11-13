//! One OpenVPN session: the link to the server, the control channel, the
//! data channel's keys and the stack behind the assigned address, driven by
//! one task. The task keeps the session alive with the pings the server asks
//! for, ends it when the server falls silent past `ping-restart`, when it
//! says so, or after the tunnel has carried nothing for a while; the
//! connector opens another on the next dial.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::config::{ClientConfig, Remote};
use super::control::{Control, Ending, Event};
use super::data::{occ_exit, DataKeys, Payload, PING};
use super::exchange::{Credentials, Pushed};
use super::link::{self, LinkPacket, LinkSender};
use super::stack::{Addresses, Stack, UdpPorts};
use super::wire::{key_id, opcode, P_DATA_V1, P_DATA_V2};
use crate::egress::EgressRuntime;
use crate::outbound::{Dialer, OutboundError, OutboundStage};
use crate::packet::tcp::{CapturedTcpStream, EngineWake};

/// How long the previous key still opens packets after a renegotiation
/// (`transition-window`).
const TRANSITION_WINDOW: Duration = Duration::from_secs(60);
/// A tunnel nothing has used for this long ends.
const IDLE_CLOSE: Duration = Duration::from_secs(300);
/// Packets taken from the link per turn of the task. The stack acknowledges
/// each flow's data once a turn, so an ACK covers at most about 64 KiB, as a
/// Linux receiver's GRO aggregate does. An ACK for every packet slowed
/// downloads: a userspace OpenVPN server spends as much on an ACK as on a
/// data packet, and so did this side.
const LINK_BATCH: usize = 48;

enum Command {
    Connect {
        peer: SocketAddr,
        reply: oneshot::Sender<io::Result<CapturedTcpStream>>,
    },
    Packet(Vec<u8>),
}

/// A session that is up, as the connector holds it.
pub(crate) struct Tunnel {
    commands: mpsc::UnboundedSender<Command>,
    pub(super) addresses: Addresses,
    pub(super) pushed: Pushed,
    pub(super) udp: UdpPorts,
    closed: CancellationToken,
    /// The runtime the session's tasks run on: the one that opened it.
    pub(super) runtime: tokio::runtime::Id,
}

fn gone() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "the OpenVPN tunnel closed")
}

impl Tunnel {
    pub(super) fn is_open(&self) -> bool {
        !self.closed.is_cancelled()
    }

    /// Ends the session; the server hears of it.
    pub(super) fn close(&self) {
        self.closed.cancel();
    }

    /// A TCP connection to `peer` through the tunnel, once established.
    pub(super) async fn connect(&self, peer: SocketAddr) -> io::Result<CapturedTcpStream> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Command::Connect { peer, reply })
            .map_err(|_| gone())?;
        let stream = answer.await.map_err(|_| gone())??;
        stream.established().await?;
        Ok(stream)
    }

    /// Sends one IP packet through the tunnel.
    pub(super) fn send(&self, packet: Vec<u8>) -> io::Result<()> {
        self.commands
            .send(Command::Packet(packet))
            .map_err(|_| gone())
    }

    pub(super) fn reaches(&self, ip: IpAddr) -> bool {
        self.addresses.local_for(ip).is_some()
    }
}

/// Opens a session to `remote`: returns once the server has authenticated
/// the client, pushed its configuration and keyed the data channel.
pub(super) async fn open(
    egress: &EgressRuntime,
    dialer: &Dialer,
    remote: &Remote,
    config: &ClientConfig,
    tls: Arc<rustls::ClientConfig>,
    credentials: Option<Credentials>,
) -> Result<Arc<Tunnel>, OutboundError> {
    let closed = CancellationToken::new();
    let (link, packets) = link::connect(egress, dialer, remote, closed.clone()).await?;
    let now = Instant::now();
    let control = Control::new(config, tls, credentials, link.is_stream(), now);
    let (commands, command_rx) = mpsc::unbounded_channel();
    let (up, answer) = oneshot::channel();
    let driver = Driver {
        link,
        packets,
        commands: command_rx,
        control,
        closed: closed.clone(),
        retire: egress.policy_cancel(),
        ping: config.ping,
        ping_restart: config.ping_restart,
        exit_notify: config.explicit_exit_notify,
        udp: UdpPorts::default(),
    };
    egress
        .spawn_policy_task(driver.run(up, commands))
        .map_err(|error| OutboundError::new(OutboundStage::Local, error))?;
    match answer.await {
        Ok(Ok(tunnel)) => Ok(tunnel),
        Ok(Err(ending)) => Err(refused(&ending)),
        Err(_) => Err(OutboundError::new(
            OutboundStage::Local,
            "the OpenVPN session ended before it came up",
        )),
    }
}

/// A session that ended before it came up, as a dial failure of the node.
fn refused(ending: &Ending) -> OutboundError {
    let stage = match ending {
        Ending::AuthFailed(_) => OutboundStage::HopAuth,
        Ending::Failed(reason) if reason.starts_with("TLS") => OutboundStage::HopProtocol,
        _ => OutboundStage::HopConnect,
    };
    OutboundError::new(stage, format!("OpenVPN: {ending}"))
}

/// The keyed data channel once the session is up.
struct Session {
    stack: Stack,
    wake: Arc<EngineWake>,
    keys: DataKeys,
    retiring: Option<(DataKeys, Instant)>,
    peer_id: Option<u32>,
    ping: Option<Duration>,
    ping_restart: Option<Duration>,
    cc_exit: bool,
    idle_since: Option<Instant>,
}

struct Driver {
    link: LinkSender,
    packets: mpsc::Receiver<LinkPacket>,
    commands: mpsc::UnboundedReceiver<Command>,
    control: Control,
    closed: CancellationToken,
    retire: CancellationToken,
    ping: Option<Duration>,
    ping_restart: Option<Duration>,
    exit_notify: bool,
    udp: UdpPorts,
}

/// Why the task stopped.
enum Stop {
    Ended(Ending),
    /// Closed from this side: dropped, idle, a changed network, retired.
    Closed,
    Link(String),
}

impl Driver {
    async fn run(
        mut self,
        up: oneshot::Sender<Result<Arc<Tunnel>, Ending>>,
        commands: mpsc::UnboundedSender<Command>,
    ) {
        let mut up = Some((up, commands));
        let mut session: Option<Session> = None;
        let mut last_sent = Instant::now();
        let mut last_received = Instant::now();
        let stop = 'run: loop {
            let now = Instant::now();
            for packet in self.control.transmit(now) {
                if let Err(error) = self.link.send(&packet).await {
                    break 'run Stop::Link(error.to_string());
                }
                last_sent = now;
            }
            while let Some(event) = self.control.event() {
                match event {
                    Event::Up(pushed, keys) => {
                        let addresses = Addresses {
                            ipv4: pushed.ipv4,
                            ipv6: pushed.ipv6,
                        };
                        let stack = Stack::new(addresses, self.udp.clone());
                        let Some((up, commands)) = up.take() else {
                            continue;
                        };
                        let tunnel = Arc::new(Tunnel {
                            commands,
                            addresses,
                            pushed: pushed.clone(),
                            udp: self.udp.clone(),
                            closed: self.closed.clone(),
                            runtime: tokio::runtime::Handle::current().id(),
                        });
                        session = Some(Session {
                            wake: stack.wake(),
                            stack,
                            keys,
                            retiring: None,
                            peer_id: pushed.peer_id,
                            ping: pushed.ping.or(self.ping),
                            ping_restart: pushed.ping_restart.or(self.ping_restart),
                            cc_exit: pushed.cc_exit,
                            idle_since: None,
                        });
                        let _ = up.send(Ok(tunnel));
                    }
                    Event::Rekeyed(keys) => {
                        if let Some(session) = session.as_mut() {
                            let old = std::mem::replace(&mut session.keys, keys);
                            session.retiring = Some((old, now + TRANSITION_WINDOW));
                        }
                    }
                    Event::Ended(ending) => break 'run Stop::Ended(ending),
                }
            }
            let mut deadline = self.control.next_deadline();
            if let Some(session) = session.as_mut() {
                for packet in session.stack.poll(now) {
                    let Some(sealed) = session.keys.seal(session.peer_id, &packet) else {
                        break 'run Stop::Link("the data channel's packet ids ran out".into());
                    };
                    if let Err(error) = self.link.send(&sealed).await {
                        break 'run Stop::Link(error.to_string());
                    }
                    last_sent = now;
                }
                if let Some(ping) = session.ping {
                    if now >= last_sent + ping {
                        if let Some(sealed) = session.keys.seal(session.peer_id, &PING) {
                            if let Err(error) = self.link.send(&sealed).await {
                                break 'run Stop::Link(error.to_string());
                            }
                        }
                        last_sent = now;
                    }
                    deadline = earliest(deadline, last_sent + ping);
                }
                if let Some(restart) = session.ping_restart {
                    if now >= last_received + restart {
                        break 'run Stop::Ended(Ending::Failed(
                            "the server stopped answering (ping-restart)".into(),
                        ));
                    }
                    deadline = earliest(deadline, last_received + restart);
                }
                if session.stack.is_idle() {
                    let since = *session.idle_since.get_or_insert(now);
                    if now >= since + IDLE_CLOSE {
                        break 'run Stop::Closed;
                    }
                    deadline = earliest(deadline, since + IDLE_CLOSE);
                } else {
                    session.idle_since = None;
                }
                if session
                    .retiring
                    .as_ref()
                    .is_some_and(|(_, until)| now >= *until)
                {
                    session.retiring = None;
                }
                deadline = earliest(deadline, session.stack.next_deadline());
            }
            let wake = session.as_ref().map(|session| Arc::clone(&session.wake));
            let woken = async {
                match &wake {
                    Some(wake) => wake.notify.notified().await,
                    None => std::future::pending().await,
                }
            };
            let sleep = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => std::future::pending().await,
                }
            };
            // Before it is up, a session nobody waits for any more ends.
            let abandoned = async {
                match up.as_mut() {
                    Some((up, _)) => up.closed().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                () = self.closed.cancelled() => break 'run Stop::Closed,
                () = self.retire.cancelled() => break 'run Stop::Closed,
                () = abandoned => break 'run Stop::Closed,
                packet = self.packets.recv() => {
                    let Some(packet) = packet else {
                        break 'run Stop::Link("the link to the server closed".into());
                    };
                    last_received = Instant::now();
                    let mut next = Some(packet);
                    let mut taken = 0;
                    while let Some(packet) = next.take() {
                        if let Some(stop) =
                            self.dispatch(packet.bytes, session.as_mut(), last_received)
                        {
                            break 'run stop;
                        }
                        taken += 1;
                        if taken < LINK_BATCH {
                            next = self.packets.try_recv().ok();
                        }
                    }
                }
                command = self.commands.recv() => match command {
                    Some(Command::Connect { peer, reply }) => {
                        let stream = match session.as_mut() {
                            Some(session) => session.stack.connect(peer, Instant::now()),
                            None => Err(gone()),
                        };
                        let _ = reply.send(stream);
                    }
                    Some(Command::Packet(packet)) => {
                        if let Some(session) = session.as_mut() {
                            if let Some(sealed) = session.keys.seal(session.peer_id, &packet) {
                                if let Err(error) = self.link.send(&sealed).await {
                                    break 'run Stop::Link(error.to_string());
                                }
                                last_sent = Instant::now();
                            }
                        }
                    }
                    // Every handle on the tunnel is gone: nothing can use the
                    // session any more.
                    None => break 'run Stop::Closed,
                },
                () = woken => {}
                () = sleep => {}
            }
        };
        // The server learns at once that the session is gone instead of after
        // its ping-restart: over the control channel, or as an OCC message.
        if matches!(stop, Stop::Closed) {
            if let Some(session) = session.as_mut() {
                if session.cc_exit {
                    self.control.exit();
                    for packet in self.control.transmit(Instant::now()) {
                        let _ = self.link.send(&packet).await;
                    }
                } else if self.exit_notify {
                    if let Some(sealed) = session.keys.seal(session.peer_id, &occ_exit()) {
                        let _ = self.link.send(&sealed).await;
                    }
                }
            }
        }
        self.closed.cancel();
        if let Some((up, _)) = up.take() {
            let ending = match stop {
                Stop::Ended(ending) => ending,
                Stop::Closed => Ending::Failed("the session was closed".into()),
                Stop::Link(reason) => Ending::Failed(format!("the link failed: {reason}")),
            };
            let _ = up.send(Err(ending));
        }
    }

    /// Takes one packet from the server; returns why the session ends, if
    /// it does.
    fn dispatch(
        &mut self,
        packet: Vec<u8>,
        session: Option<&mut Session>,
        now: Instant,
    ) -> Option<Stop> {
        let first = *packet.first()?;
        if !matches!(opcode(first), P_DATA_V1 | P_DATA_V2) {
            self.control.receive(&packet, now);
            return None;
        }
        let session = session?;
        let key = key_id(first);
        let keys = if session.keys.key_id() == key {
            &mut session.keys
        } else {
            match session.retiring.as_mut() {
                Some((keys, _)) if keys.key_id() == key => keys,
                _ => return None,
            }
        };
        match keys.open(&packet)? {
            Payload::Ip(ip) => session.stack.input(ip, now),
            Payload::Exit => return Some(Stop::Ended(Ending::Exit)),
            Payload::Ping | Payload::Other => {}
        }
        None
    }
}

fn earliest(deadline: Option<Instant>, candidate: impl Into<Option<Instant>>) -> Option<Instant> {
    match (deadline, candidate.into()) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
