use crate::outbound::{
    recv_datagram, DatagramError, DatagramFuture, PumpDatagrams, PumpFrom, PumpTo,
};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Waker};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::egress::EgressRuntime;
use crate::outbound::{
    chained_datagrams, dial_carrier_via, held_until_closed, write_early_data, BoxedOutboundStream,
    DatagramCodec, Dialer, Hop, OutboundAuth, OutboundConnector, OutboundDatagramReceiver,
    OutboundDatagramSender, OutboundDatagramTransport, OutboundError, OutboundFuture,
    OutboundResultExt, OutboundStage, ProxyTls,
};
use crate::target::{parse_socks_address, ConnectTarget};

/// SOCKS5 proxy hop: CONNECT streams and UDP ASSOCIATE datagrams.
#[derive(Debug)]
pub(crate) struct Socks5ProxyConnector {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) dialer: Dialer,
    pub(crate) auth: Option<OutboundAuth>,
    /// Wraps the control connection; relay datagrams stay plain UDP.
    pub(crate) tls: ProxyTls,
    pub(crate) udp: bool,
}

impl OutboundConnector for Socks5ProxyConnector {
    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let mut stream = self.connect_tunnel(egress, target).await?;
            // The proxy already reported the target connected; a failure now
            // is the tunnel to the target closing, not the proxy failing.
            write_early_data(&mut stream, early_data)
                .await
                .at(OutboundStage::Target)?;
            Ok(stream)
        })
    }

    /// SOCKS5 UDP ASSOCIATE (RFC 1928 §7): one control connection plus one
    /// relay socket per session. The association lives exactly as long as
    /// the control connection, so the receive half holds it and ends the
    /// transport when the proxy closes it — the next datagram on the flow
    /// rebuilds the session. A chained node's control connection and relay
    /// datagrams take the same hop, resolved once, so the proxy sees both
    /// come from one host.
    fn connect_datagram<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        _target: &'a ConnectTarget,
    ) -> OutboundFuture<'a, OutboundDatagramTransport> {
        Box::pin(async move {
            let hop = self.dialer.hop(egress, &self.server())?;
            let (mut control, proxy_addr) = self.handshake(egress, hop.as_ref()).await?;
            let relay_addr = request_socks5_udp_associate(&mut control).await?;
            if let Some(hop) = hop {
                // A wildcard BND.ADDR means the host the control connection
                // reached, which only the hop knows by the node's name.
                let relay = ConnectTarget {
                    host: if relay_addr.ip().is_unspecified() {
                        self.host.clone()
                    } else {
                        relay_addr.ip().to_string()
                    },
                    port: relay_addr.port(),
                };
                let datagrams = hop.datagrams(&relay).await?;
                return Ok(chained_datagrams(
                    datagrams,
                    relay,
                    Arc::new(Socks5Codec),
                    Some(control),
                ));
            }
            let proxy_addr = proxy_addr.ok_or_else(|| {
                OutboundError::new(
                    OutboundStage::Local,
                    "the SOCKS5 control connection has no peer address",
                )
            })?;

            // The relay socket dials the proxy's bound relay endpoint, never
            // the target: the target rides in every datagram's request
            // header instead. A wildcard BND.ADDR means "the same host the
            // control connection reached".
            let relay_ip = if relay_addr.ip().is_unspecified() {
                proxy_addr.ip()
            } else {
                relay_addr.ip()
            };
            let socket = Arc::new(
                egress
                    .connect_udp_host(
                        &relay_ip.to_string(),
                        relay_addr.port(),
                        "SOCKS5 UDP relay socket",
                    )
                    .await
                    .map_err(OutboundError::hop_dial)?,
            );

            let io = Arc::new(Socks5UdpIo {
                socket,
                pump: OnceLock::new(),
            });
            Ok(OutboundDatagramTransport {
                sender: Box::new(Socks5DatagramSender(Arc::clone(&io))),
                receiver: Box::new(Socks5DatagramReceiver { io, control }),
            })
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn udp_enabled(&self) -> bool {
        self.udp
    }
}

/// The RFC 1928 §7 header on every relay datagram: [RSV RSV FRAG], then the
/// target or the reply's origin, then the payload.
struct Socks5Codec;

impl DatagramCodec for Socks5Codec {
    fn seal(&self, target: &ConnectTarget, payload: &[u8]) -> Result<Vec<u8>, DatagramError> {
        let mut datagram = vec![0x00, 0x00, 0x00];
        datagram.extend(target.socks_address()?);
        datagram.extend_from_slice(payload);
        Ok(datagram)
    }

    fn open(&self, packet: &mut [u8]) -> Option<(ConnectTarget, Vec<u8>)> {
        socks5_udp_reply(packet)
    }
}

/// One association's relay socket, connected to the proxy's relay endpoint.
/// Every datagram carries the RFC 1928 §7 request header with its own
/// target, so one association relays to every remote the client addresses
/// (EIM). The session actor sends and reads through it, and once a captured
/// flow's association is learned, the packet pump does so itself.
struct Socks5UdpIo {
    socket: Arc<UdpSocket>,
    /// Set once the packet pump reads the socket (see
    /// [`PumpDatagrams::hand_reads_to`]).
    pump: OnceLock<Waker>,
}

impl Socks5UdpIo {
    /// Asks for the next datagram to wake the pump; whether one is waiting
    /// already, in which case no wakeup is registered.
    fn arm(&self) -> bool {
        self.pump.get().is_some_and(|waker| {
            self.socket
                .poll_recv_ready(&mut Context::from_waker(waker))
                .is_ready()
        })
    }
}

impl PumpDatagrams for Socks5UdpIo {
    fn try_send(&self, to: &PumpTo, payload: &[u8]) -> io::Result<()> {
        // [RSV RSV FRAG], the target, the payload.
        let mut datagram = Vec::with_capacity(3 + 19 + payload.len());
        datagram.extend_from_slice(&[0x00, 0x00, 0x00]);
        to.push_socks_address(&mut datagram)?;
        datagram.extend_from_slice(payload);
        // Sent at once: a new socket's readiness starts empty, so a
        // non-blocking send through the reactor would refuse it.
        socket2::SockRef::from(&*self.socket)
            .send(&datagram)
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
            // Undecodable and fragmented datagrams are skipped like lost
            // ones, as [`socks5_udp_reply`] does; the reply's own address is
            // its origin (EIF).
            if read < 4 || buffer[2] != 0x00 {
                continue;
            }
            let Some((from, address)) = PumpFrom::from_socks_address(&buffer[3..read]) else {
                continue;
            };
            let start = 3 + address;
            buffer.copy_within(start..read, 0);
            let length = read - start;
            return Ok((length, from, length));
        }
    }
}

struct Socks5DatagramSender(Arc<Socks5UdpIo>);

impl OutboundDatagramSender for Socks5DatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        crate::outbound::DatagramSendCancellation::AtomicDatagram
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            let datagram = Socks5Codec.seal(target, payload)?;
            self.0
                .socket
                .send(&datagram)
                .await
                .map(|_| ())
                .map_err(DatagramError::NativeSocket)
        })
    }
}

struct Socks5DatagramReceiver {
    io: Arc<Socks5UdpIo>,
    /// Held for the association's lifetime (RFC 1928 §7): the proxy drops
    /// the relay when this connection ends, so its EOF ends the transport.
    control: BoxedOutboundStream,
}

impl OutboundDatagramReceiver for Socks5DatagramReceiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            let Self { io, control } = self;
            // The proxy ends the association by closing the control
            // connection; stray bytes on it do not.
            let closed = held_until_closed(Some(control));
            tokio::pin!(closed);
            loop {
                // Biased: drain responses the relay already delivered before
                // honoring a teardown racing them on the control connection.
                tokio::select! {
                    biased;
                    received = recv_datagram(&io.socket) => match received {
                        // Undecodable and fragmented datagrams are skipped,
                        // not fatal (receiver contract).
                        Ok((buffer, read)) => match socks5_udp_reply(&buffer[..read]) {
                            Some(reply) => return Ok(Some(reply)),
                            None => continue,
                        },
                        Err(error) => return Err(DatagramError::NativeSocket(error)),
                    },
                    closed = &mut closed => return closed.map(|()| None),
                }
            }
        })
    }

    fn pump_datagrams(&self) -> Option<Arc<dyn PumpDatagrams>> {
        Some(Arc::clone(&self.io) as Arc<dyn PumpDatagrams>)
    }

    fn ended(&mut self) -> DatagramFuture<'_, ()> {
        Box::pin(held_until_closed(Some(&mut self.control)))
    }
}

/// Splits one relay datagram (RFC 1928 §7 reply form) into the remote it came
/// from and its payload. `None` skips it: undecodable, or fragmented
/// (FRAG != 0) — fragment reassembly is optional per the RFC and unsupported
/// here. The reply's own address is the framing source (EIF), so a proxy
/// forwarding a hole-punched peer's datagram delivers it to the client.
fn socks5_udp_reply(datagram: &[u8]) -> Option<(ConnectTarget, Vec<u8>)> {
    if datagram.len() < 4 || datagram[2] != 0x00 {
        return None;
    }
    let (remote, consumed) = parse_socks_address(&datagram[3..]).ok()?;
    let payload = datagram.get(3 + consumed..)?;
    Some((remote, payload.to_vec()))
}

impl Socks5ProxyConnector {
    fn server(&self) -> ConnectTarget {
        ConnectTarget {
            host: self.host.clone(),
            port: self.port,
        }
    }

    async fn connect_tunnel(
        &self,
        egress: &EgressRuntime,
        target: &ConnectTarget,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        let hop = self.dialer.hop(egress, &self.server())?;
        let (mut stream, _) = self.handshake(egress, hop.as_ref()).await?;
        let mut request = vec![0x05, 0x01, 0x00];
        request.extend(target.socks_address().at(OutboundStage::Local)?);
        stream
            .write_all(&request)
            .await
            .at(OutboundStage::HopConnect)?;
        stream.flush().await.at(OutboundStage::HopConnect)?;
        read_socks5_reply(&mut stream, connect_reply_stage).await?;
        Ok(stream)
    }

    /// Dials the proxy through `hop` or from this host and completes method
    /// negotiation plus authentication — the shared prefix of the CONNECT
    /// and UDP ASSOCIATE conversations. Returns the control connection with
    /// the proxy's address when this host connected to it.
    async fn handshake(
        &self,
        egress: &EgressRuntime,
        hop: Option<&Hop>,
    ) -> Result<(BoxedOutboundStream, Option<SocketAddr>), OutboundError> {
        let (stream, proxy_addr) = dial_carrier_via(
            egress,
            hop,
            self.server(),
            "SOCKS5 proxy",
            self.tls.client()?,
        )
        .await?;
        let stream = negotiate(stream, self.auth.as_ref()).await?;
        Ok((stream, proxy_addr))
    }
}

/// Whom a refused CONNECT is evidence against (RFC 1928 §6). Codes 1-6 are
/// the proxy's verdict on reaching the target; many servers report any
/// failed target connect as a general failure (1), so it is not charged to
/// the proxy either. Codes 7-8 are the proxy failing the request itself.
fn connect_reply_stage(reply: u8) -> OutboundStage {
    match reply {
        0x01..=0x06 => OutboundStage::Target,
        _ => OutboundStage::HopProtocol,
    }
}

/// Method negotiation plus authentication over a dialed control connection.
async fn negotiate(
    mut stream: BoxedOutboundStream,
    auth: Option<&OutboundAuth>,
) -> Result<BoxedOutboundStream, OutboundError> {
    let methods = if auth.is_some() {
        [0x05, 0x01, 0x02]
    } else {
        [0x05, 0x01, 0x00]
    };
    stream
        .write_all(&methods)
        .await
        .at(OutboundStage::HopConnect)?;
    stream.flush().await.at(OutboundStage::HopConnect)?;
    let mut method = [0_u8; 2];
    stream
        .read_exact(&mut method)
        .await
        .at(OutboundStage::HopConnect)?;
    match (auth, method) {
        (None, [0x05, 0x00]) => {}
        (Some(auth), [0x05, 0x02]) => authenticate_socks5_proxy(&mut stream, auth).await?,
        (Some(_), [0x05, 0x00]) => {
            return Err(OutboundError::new(
                OutboundStage::HopProtocol,
                "SOCKS5 proxy selected no-auth while credentials are configured",
            ));
        }
        // The proxy accepts none of the offered methods: it wants
        // credentials we do not have, or not the kind we offered.
        (_, method) => {
            return Err(OutboundError::new(
                OutboundStage::HopAuth,
                format!("SOCKS5 proxy rejected requested method: {method:?}"),
            ));
        }
    }
    Ok(stream)
}

/// Requests UDP ASSOCIATE and returns the proxy's relay endpoint. DST.ADDR
/// and DST.PORT name the client's send endpoint, all zeros when unknown —
/// the relay socket binds only after this exchange reveals its peer.
async fn request_socks5_udp_associate(
    control: &mut BoxedOutboundStream,
) -> Result<SocketAddr, OutboundError> {
    control
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .at(OutboundStage::HopConnect)?;
    control.flush().await.at(OutboundStage::HopConnect)?;
    // Refusing an association names no target: the proxy cannot relay UDP.
    read_socks5_reply(control, |_| OutboundStage::HopProtocol)
        .await?
        .ok_or_else(|| {
            OutboundError::new(
                OutboundStage::HopProtocol,
                "SOCKS5 proxy returned a domain relay endpoint for UDP ASSOCIATE",
            )
        })
}

async fn authenticate_socks5_proxy(
    stream: &mut BoxedOutboundStream,
    auth: &OutboundAuth,
) -> Result<(), OutboundError> {
    let username = auth.username.as_bytes();
    let password = auth.password.as_bytes();
    if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
        return Err(OutboundError::new(
            OutboundStage::Config,
            "SOCKS5 username/password must be <= 255 bytes",
        ));
    }

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream
        .write_all(&request)
        .await
        .at(OutboundStage::HopConnect)?;
    stream.flush().await.at(OutboundStage::HopConnect)?;

    let mut response = [0_u8; 2];
    stream
        .read_exact(&mut response)
        .await
        .at(OutboundStage::HopConnect)?;
    if response != [0x01, 0x00] {
        return Err(OutboundError::new(
            OutboundStage::HopAuth,
            format!("SOCKS5 username/password auth failed: {response:?}"),
        ));
    }

    Ok(())
}

/// Reads one SOCKS5 reply (RFC 1928 §6) and returns BND.ADDR/BND.PORT when
/// the proxy sent it in socket-address form (domain form yields `None`).
/// CONNECT ignores the bound address; UDP ASSOCIATE requires it. A refusal is
/// classified by the request that drew it.
async fn read_socks5_reply(
    stream: &mut BoxedOutboundStream,
    refusal_stage: impl Fn(u8) -> OutboundStage,
) -> Result<Option<SocketAddr>, OutboundError> {
    let mut head = [0_u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .at(OutboundStage::HopConnect)?;
    if head[0] != 0x05 {
        return Err(OutboundError::new(
            OutboundStage::HopProtocol,
            format!("invalid SOCKS5 proxy reply version {}", head[0]),
        ));
    }
    if head[1] != 0x00 {
        return Err(OutboundError::new(
            refusal_stage(head[1]),
            format!("SOCKS5 proxy request failed with status {}", head[1]),
        ));
    }

    let bound_ip = match head[3] {
        0x01 => {
            let mut address = [0_u8; 4];
            stream
                .read_exact(&mut address)
                .await
                .at(OutboundStage::HopConnect)?;
            Some(IpAddr::V4(Ipv4Addr::from(address)))
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .at(OutboundStage::HopConnect)?;
            let mut address = vec![0_u8; length[0] as usize];
            stream
                .read_exact(&mut address)
                .await
                .at(OutboundStage::HopConnect)?;
            None
        }
        0x04 => {
            let mut address = [0_u8; 16];
            stream
                .read_exact(&mut address)
                .await
                .at(OutboundStage::HopConnect)?;
            Some(IpAddr::V6(Ipv6Addr::from(address)))
        }
        unsupported => {
            return Err(OutboundError::new(
                OutboundStage::HopProtocol,
                format!("unsupported SOCKS5 reply address type {unsupported}"),
            ))
        }
    };

    let mut port = [0_u8; 2];
    stream
        .read_exact(&mut port)
        .await
        .at(OutboundStage::HopConnect)?;
    Ok(bound_ip.map(|ip| SocketAddr::new(ip, u16::from_be_bytes(port))))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use serde_json::{json, Value as JsonValue};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::{timeout, Duration};

    use super::*;
    use crate::capture::NativeCoreCaptureConfig;
    use crate::egress::NativeCoreEgressConfig;
    use crate::inbound::listener::CoreSessionManager;
    use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
    use crate::protocols::socks5::acceptor::write_socks5_reply;
    use crate::runtime::{NativeCoreRuntime, NativeCoreSessionState, RuntimeSnapshot};
    use crate::self_test::{run_connect_client, serve_one_echo};
    use crate::udp::{drain_pending_udp_flow_responses, send_udp_flow_datagram, UdpDatagram};

    #[test]
    fn a_refused_connect_names_whom_it_blames() {
        for reply in 0x01..=0x06 {
            assert_eq!(connect_reply_stage(reply), OutboundStage::Target, "{reply}");
        }
        for reply in [0x07, 0x08, 0x09] {
            assert_eq!(
                connect_reply_stage(reply),
                OutboundStage::HopProtocol,
                "{reply}"
            );
        }
    }

    #[tokio::test]
    async fn native_core_routes_through_socks5_proxy_outbound() {
        let payload = b"socks5-proxy-outbound-poc";
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo target");
        let target_addr = target_listener.local_addr().expect("target addr");
        let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake SOCKS5 proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let proxy_task = tokio::spawn(async move { serve_one_socks5_proxy(proxy_listener).await });
        let manager = CoreSessionManager::default();
        let running = manager
            .start(proxy_profile(
                "SocksProxy",
                ProxyProtocol::Socks5,
                proxy_addr,
            ))
            .await
            .expect("manager starts");
        let core_addr = running
            .listen_addr
            .as_deref()
            .expect("listen addr")
            .parse::<SocketAddr>()
            .expect("valid listen addr");

        let received = run_connect_client(core_addr, target_addr, payload)
            .await
            .expect("SOCKS5 proxy outbound tunnels");

        assert_eq!(received, payload);
        echo_task.await.expect("echo join").expect("echo completes");
        proxy_task
            .await
            .expect("proxy join")
            .expect("proxy completes");
        manager.stop();
    }

    #[tokio::test]
    async fn native_core_sends_socks5_proxy_username_password_auth() {
        let payload = b"socks5-proxy-auth-poc";
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind echo target");
        let target_addr = target_listener.local_addr().expect("target addr");
        let echo_task = tokio::spawn(async move { serve_one_echo(target_listener).await });
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake SOCKS5 proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let proxy_task = tokio::spawn(async move {
            serve_one_socks5_proxy_with_auth(proxy_listener, "user", "pass").await
        });
        let manager = CoreSessionManager::default();
        let running = manager
            .start(proxy_profile_with_options(
                "SocksProxy",
                ProxyProtocol::Socks5,
                proxy_addr,
                json!({ "username": "user", "password": "pass" }),
            ))
            .await
            .expect("manager starts");
        let core_addr = running
            .listen_addr
            .as_deref()
            .expect("listen addr")
            .parse::<SocketAddr>()
            .expect("valid listen addr");

        let received = run_connect_client(core_addr, target_addr, payload)
            .await
            .expect("SOCKS5 proxy auth outbound tunnels");

        assert_eq!(received, payload);
        echo_task.await.expect("echo join").expect("echo completes");
        proxy_task
            .await
            .expect("proxy join")
            .expect("proxy completes");
        manager.stop();
    }

    #[tokio::test]
    async fn native_core_relays_udp_through_socks5_udp_associate() {
        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind udp echo target");
        let target_addr = target.local_addr().expect("target addr");
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 2048];
            loop {
                let Ok((read, peer)) = target.recv_from(&mut buffer).await else {
                    break;
                };
                if target.send_to(&buffer[..read], peer).await.is_err() {
                    break;
                }
            }
        });
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake SOCKS5 proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let proxy_task =
            tokio::spawn(async move { serve_one_socks5_udp_proxy(proxy_listener, 2, false).await });
        let snapshot = RuntimeSnapshot::compile(
            &proxy_profile_with_options(
                "SocksProxy",
                ProxyProtocol::Socks5,
                proxy_addr,
                json!({ "udp": true }),
            ),
            NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default(),
            None,
            crate::policy_group::GroupStateTable::default(),
        );
        let runtime =
            NativeCoreRuntime::pinned(Arc::new(snapshot), NativeCoreSessionState::default());

        let source: SocketAddr = "127.0.0.1:54321".parse().expect("source");
        for payload in [
            b"first-socks5-udp-datagram".as_slice(),
            b"second-socks5-udp-datagram".as_slice(),
        ] {
            let flow_id = "socks5-udp-flow";
            let outcome = send_udp_flow_datagram(
                &runtime,
                UdpDatagram {
                    flow_id: Some(flow_id.into()),
                    pump_queue: None,
                    inbound: "tun",
                    user: None,
                    source,
                    target: ConnectTarget {
                        host: target_addr.ip().to_string(),
                        port: target_addr.port(),
                    },
                    payload: payload.to_vec(),
                    process_name: None,
                    process_path: None,
                },
            )
            .await
            .expect("SOCKS5 UDP outbound sends");
            assert!(outcome.enqueued);
            let response = drain_pending_udp_flow_responses(&runtime, 16, Duration::from_secs(5))
                .await
                .into_iter()
                .find(|response| response.flow_id == flow_id)
                .expect("SOCKS5 UDP response");
            assert_eq!(response.payload, payload);
            assert!(outcome.enqueued);
            assert_eq!(
                runtime
                    .udp_sessions()
                    .session_for_flow(&flow_id)
                    .unwrap()
                    .outbound,
                "SocksProxy"
            );
        }
        // Both datagrams shared one association: one control connection,
        // one relay socket.
        assert_eq!(runtime.udp_sessions().session_socket_count(), 1);
        // Dropping the runtime tears down the session actor, whose control
        // connection EOF releases the proxy.
        drop(runtime);
        proxy_task
            .await
            .expect("proxy join")
            .expect("proxy completes");
    }

    /// The association lives exactly as long as the control connection
    /// (RFC 1928 §7): the proxy dropping it must end the transport, not
    /// leave the receiver parked forever.
    #[tokio::test]
    async fn socks5_udp_transport_ends_when_proxy_closes_control_connection() {
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind fake SOCKS5 proxy");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let proxy_task =
            tokio::spawn(async move { serve_one_socks5_udp_proxy(proxy_listener, 0, true).await });
        let connector = Socks5ProxyConnector {
            host: proxy_addr.ip().to_string(),
            port: proxy_addr.port(),
            dialer: Dialer::default(),
            auth: None,
            tls: ProxyTls::PLAIN,
            udp: true,
        };
        let egress = crate::egress::EgressRuntime::default();
        let target = ConnectTarget {
            host: "192.0.2.9".into(),
            port: 4433,
        };

        let mut transport = connector
            .connect_datagram(&egress, &target)
            .await
            .expect("UDP ASSOCIATE succeeds");
        proxy_task
            .await
            .expect("proxy join")
            .expect("proxy completes");

        let ended = timeout(Duration::from_secs(5), transport.receiver.recv())
            .await
            .expect("transport end timeout")
            .expect("transport end is quiet");
        assert!(ended.is_none(), "control EOF must end the transport");
    }

    #[tokio::test]
    async fn a_scoped_ipv6_target_is_refused_rather_than_sent_without_its_zone() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        socket.connect(socket.local_addr().unwrap()).await.unwrap();
        let io = Arc::new(Socks5UdpIo {
            socket: Arc::new(socket),
            pump: OnceLock::new(),
        });
        let target = ConnectTarget {
            host: "fe80::1%en0".into(),
            port: 53,
        };
        let error = Socks5DatagramSender(Arc::clone(&io))
            .send(&target, b"query")
            .await
            .expect_err("a zone means nothing at the proxy");
        assert!(error.to_string().contains("scoped IPv6"), "{error}");
        let scoped = PumpTo::Addr("[fe80::1%2]:53".parse().unwrap());
        let error = io
            .try_send(&scoped, b"query")
            .expect_err("nor from the packet pump");
        assert!(error.to_string().contains("scoped IPv6"), "{error}");
    }

    /// The packet pump reads a relay datagram as its payload and the sender
    /// the reply header names, skipping what it cannot decode.
    #[tokio::test]
    async fn the_pump_reads_replies_by_their_header() {
        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        socket.connect(relay.local_addr().unwrap()).await.unwrap();
        let client = socket.local_addr().unwrap();
        let io = Socks5UdpIo {
            socket: Arc::new(socket),
            pump: OnceLock::new(),
        };

        let to = PumpTo::Addr("[2001:db8::7]:443".parse().unwrap());
        io.try_send(&to, b"hello").unwrap();
        let mut buffer = [0_u8; 2048];
        let read = relay.recv(&mut buffer).await.unwrap();
        let mut expected = vec![0x00, 0x00, 0x00, 0x04];
        expected.extend_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        expected.extend_from_slice(&443_u16.to_be_bytes());
        expected.extend_from_slice(b"hello");
        assert_eq!(&buffer[..read], expected);

        let mut fragment = vec![0x00, 0x00, 0x01, 0x01, 192, 0, 2, 9, 0x00, 0x35];
        fragment.extend_from_slice(b"skipped");
        let mut named = vec![0x00, 0x00, 0x00, 0x03, 11];
        named.extend_from_slice(b"example.com");
        named.extend_from_slice(&53_u16.to_be_bytes());
        named.extend_from_slice(b"answer");
        for datagram in [&b"\x00\x00"[..], &fragment, &named] {
            relay.send_to(datagram, client).await.unwrap();
        }
        let (length, from, segment) = timeout(Duration::from_secs(5), async {
            loop {
                match io.try_recv(&mut buffer) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    read => break read,
                }
            }
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..length], b"answer");
        assert_eq!(segment, length);
        assert_eq!(
            from,
            PumpFrom::Name(ConnectTarget {
                host: "example.com".into(),
                port: 53,
            })
        );
    }

    #[test]
    fn socks5_udp_reply_parses_remote_and_strips_headers_and_skips_junk() {
        let mut v4 = vec![0x00, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x35];
        v4.extend_from_slice(b"answer");
        assert_eq!(
            socks5_udp_reply(&v4),
            Some((
                ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: 0x35,
                },
                b"answer".to_vec()
            ))
        );

        let mut domain = vec![0x00, 0x00, 0x00, 0x03, 0x07];
        domain.extend_from_slice(b"example");
        domain.extend_from_slice(&[0x00, 0x35]);
        domain.extend_from_slice(b"named");
        assert_eq!(
            socks5_udp_reply(&domain),
            Some((
                ConnectTarget {
                    host: "example".into(),
                    port: 0x35,
                },
                b"named".to_vec()
            ))
        );

        let mut v6 = vec![0x00, 0x00, 0x00, 0x04];
        v6.extend_from_slice(&[0_u8; 16]);
        v6.extend_from_slice(&[0x00, 0x35]);
        v6.extend_from_slice(b"six");
        assert_eq!(
            socks5_udp_reply(&v6),
            Some((
                ConnectTarget {
                    host: "::".into(),
                    port: 0x35,
                },
                b"six".to_vec()
            ))
        );

        // Fragmented, unknown ATYP, and truncated datagrams are skipped.
        let fragmented = [0x00, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x00, 0x35, 0xff];
        assert_eq!(socks5_udp_reply(&fragmented), None);
        assert_eq!(socks5_udp_reply(&[0x00, 0x00, 0x00, 0x02, 0, 0]), None);
        assert_eq!(socks5_udp_reply(&[0x00, 0x00, 0x00, 0x01, 127, 0]), None);
    }

    /// Minimal RFC 1928 §7 proxy: one association over one control
    /// connection and `datagrams` request/response round trips. Replies
    /// with a wildcard BND.ADDR, so the client must fall back to the
    /// control connection's peer host. `close_control_when_served` picks
    /// who ends the association: the proxy (EOF right after serving) or
    /// the client (the proxy holds the control connection until the client
    /// hangs up, so responses never race a teardown).
    async fn serve_one_socks5_udp_proxy(
        listener: TcpListener,
        datagrams: usize,
        close_control_when_served: bool,
    ) -> Result<(), String> {
        let (mut control, _) = listener.accept().await.map_err(|error| error.to_string())?;
        let mut greeting = [0_u8; 3];
        control
            .read_exact(&mut greeting)
            .await
            .map_err(|error| error.to_string())?;
        if greeting != [0x05, 0x01, 0x00] {
            return Err(format!("unexpected SOCKS5 no-auth greeting: {greeting:?}"));
        }
        control
            .write_all(&[0x05, 0x00])
            .await
            .map_err(|error| error.to_string())?;

        let mut request = [0_u8; 10];
        control
            .read_exact(&mut request)
            .await
            .map_err(|error| error.to_string())?;
        if request[..4] != [0x05, 0x03, 0x00, 0x01] {
            return Err(format!("unexpected SOCKS5 UDP ASSOCIATE head: {request:?}"));
        }

        let relay = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|error| error.to_string())?;
        let relay_port = relay
            .local_addr()
            .map_err(|error| error.to_string())?
            .port();
        let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
        reply.extend_from_slice(&relay_port.to_be_bytes());
        control
            .write_all(&reply)
            .await
            .map_err(|error| error.to_string())?;

        let mut buffer = vec![0_u8; 2048];
        for _ in 0..datagrams {
            let (read, client) = relay
                .recv_from(&mut buffer)
                .await
                .map_err(|error| error.to_string())?;
            let datagram = &buffer[..read];
            if datagram.len() < 10 || datagram[..4] != [0x00, 0x00, 0x00, 0x01] {
                return Err(format!(
                    "unexpected SOCKS5 UDP request header: {datagram:?}"
                ));
            }
            let target = SocketAddr::from((
                Ipv4Addr::new(datagram[4], datagram[5], datagram[6], datagram[7]),
                u16::from_be_bytes([datagram[8], datagram[9]]),
            ));
            let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .map_err(|error| error.to_string())?;
            upstream
                .send_to(&datagram[10..], target)
                .await
                .map_err(|error| error.to_string())?;
            let mut response = vec![0_u8; 2048];
            let (received, _) = upstream
                .recv_from(&mut response)
                .await
                .map_err(|error| error.to_string())?;
            let mut wire = datagram[..10].to_vec();
            wire.extend_from_slice(&response[..received]);
            relay
                .send_to(&wire, client)
                .await
                .map_err(|error| error.to_string())?;
        }
        if !close_control_when_served {
            let mut client_eof = [0_u8; 1];
            let _ = control.read(&mut client_eof).await;
        }
        Ok(())
    }

    async fn serve_one_socks5_proxy(listener: TcpListener) -> Result<(), String> {
        let (mut client, _) = listener.accept().await.map_err(|error| error.to_string())?;
        let mut greeting = [0_u8; 3];
        client
            .read_exact(&mut greeting)
            .await
            .map_err(|error| error.to_string())?;
        if greeting != [0x05, 0x01, 0x00] {
            return Err(format!("unexpected SOCKS5 no-auth greeting: {greeting:?}"));
        }
        client
            .write_all(&[0x05, 0x00])
            .await
            .map_err(|error| error.to_string())?;

        let target = read_socks5_connect_request(&mut client).await?;
        let mut upstream = crate::egress::EgressRuntime::default()
            .connect_target_tcp(&target)
            .await
            .map_err(|error| error.to_string())?;
        write_socks5_reply(&mut client, 0x00).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn serve_one_socks5_proxy_with_auth(
        listener: TcpListener,
        expected_username: &str,
        expected_password: &str,
    ) -> Result<(), String> {
        let (mut client, _) = listener.accept().await.map_err(|error| error.to_string())?;
        let mut greeting = [0_u8; 3];
        client
            .read_exact(&mut greeting)
            .await
            .map_err(|error| error.to_string())?;
        if greeting != [0x05, 0x01, 0x02] {
            return Err(format!("unexpected SOCKS5 auth greeting: {greeting:?}"));
        }
        client
            .write_all(&[0x05, 0x02])
            .await
            .map_err(|error| error.to_string())?;

        let mut auth_version = [0_u8; 1];
        client
            .read_exact(&mut auth_version)
            .await
            .map_err(|error| error.to_string())?;
        if auth_version[0] != 0x01 {
            return Err(format!(
                "unexpected SOCKS5 auth version {}",
                auth_version[0]
            ));
        }
        let username = read_socks5_length_prefixed_string(&mut client).await?;
        let password = read_socks5_length_prefixed_string(&mut client).await?;
        if username != expected_username || password != expected_password {
            client
                .write_all(&[0x01, 0x01])
                .await
                .map_err(|error| error.to_string())?;
            return Err("unexpected SOCKS5 username/password".into());
        }
        client
            .write_all(&[0x01, 0x00])
            .await
            .map_err(|error| error.to_string())?;

        let target = read_socks5_connect_request(&mut client).await?;
        let mut upstream = crate::egress::EgressRuntime::default()
            .connect_target_tcp(&target)
            .await
            .map_err(|error| error.to_string())?;
        write_socks5_reply(&mut client, 0x00).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    async fn read_socks5_connect_request(stream: &mut TcpStream) -> Result<ConnectTarget, String> {
        let mut head = [0_u8; 4];
        stream
            .read_exact(&mut head)
            .await
            .map_err(|error| error.to_string())?;
        if head != [0x05, 0x01, 0x00, 0x01] {
            return Err(format!("unexpected SOCKS5 connect head: {head:?}"));
        }
        let mut octets = [0_u8; 4];
        stream
            .read_exact(&mut octets)
            .await
            .map_err(|error| error.to_string())?;
        let mut port = [0_u8; 2];
        stream
            .read_exact(&mut port)
            .await
            .map_err(|error| error.to_string())?;
        Ok(ConnectTarget {
            host: IpAddr::V4(Ipv4Addr::from(octets)).to_string(),
            port: u16::from_be_bytes(port),
        })
    }

    async fn read_socks5_length_prefixed_string(stream: &mut TcpStream) -> Result<String, String> {
        let mut length = [0_u8; 1];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|error| error.to_string())?;
        let mut value = vec![0_u8; length[0] as usize];
        stream
            .read_exact(&mut value)
            .await
            .map_err(|error| error.to_string())?;
        String::from_utf8(value).map_err(|error| error.to_string())
    }

    fn proxy_profile(
        name: &str,
        protocol: ProxyProtocol,
        proxy_addr: SocketAddr,
    ) -> RuntimeProfile {
        proxy_profile_with_options(name, protocol, proxy_addr, JsonValue::Null)
    }

    fn proxy_profile_with_options(
        name: &str,
        protocol: ProxyProtocol,
        proxy_addr: SocketAddr,
        options: JsonValue,
    ) -> RuntimeProfile {
        RuntimeProfile {
            dns: Default::default(),
            rule_sets: Vec::new(),
            geodata: Default::default(),
            id: "proxy-profile".into(),
            name: "proxy-profile".into(),
            traffic_policy_mode: crate::profile::TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: vec![ProxyNode {
                id: format!("proxy-{name}"),
                name: name.into(),
                protocol,
                server: Some(proxy_addr.ip().to_string()),
                port: Some(proxy_addr.port()),
                options,
            }],
            groups: Vec::new(),
            rules: vec![RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: name,
                no_resolve: false,
            }]
            .into(),
        }
    }
}
