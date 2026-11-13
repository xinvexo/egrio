//! The OpenVPN node as an `OutboundConnector`: one session to the server,
//! opened when the node is first dialed and shared by every connection
//! through it. The node names its `.ovpn` file (`config`), read each time a
//! session opens, so an edited file takes effect with the next session; TCP
//! through the TCP engine behind the session's address, UDP as datagrams
//! from a local port there. A name is resolved through the DNS servers the
//! session was pushed, as the VPN's own clients do, else like any proxy
//! endpoint's.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::rr::RecordType;
use serde_json::Value as JsonValue;
use tokio::task::{AbortHandle, JoinHandle};

use super::config::{self, ClientConfig};
use super::control::tls_config;
use super::exchange::Credentials;
use super::stack::UdpPort;
use super::tunnel::{self, Tunnel};
use crate::dns::wire;
use crate::egress::EgressRuntime;
use crate::outbound::options::{option_bool, option_string};
use crate::outbound::{
    proxy_auth, write_early_data, BoxedOutboundStream, DatagramError, DatagramFuture, Dialer,
    OutboundConnector, OutboundDatagramReceiver, OutboundDatagramSender, OutboundDatagramTransport,
    OutboundError, OutboundFuture, OutboundResultExt, OutboundStage,
};
use crate::target::ConnectTarget;

/// How long one DNS server through the tunnel has to answer.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// The node's options: where its `.ovpn` file is and the credentials it
/// answers the server with.
struct Node {
    path: PathBuf,
    credentials: Option<Credentials>,
}

/// One session's configuration, as the node's file says it.
struct Setup {
    config: ClientConfig,
    tls: Arc<rustls::ClientConfig>,
}

type Opening = JoinHandle<Result<Arc<Tunnel>, OutboundError>>;

pub(crate) struct OpenVpnConnector {
    node: Result<Arc<Node>, String>,
    dialer: Dialer,
    udp: bool,
    current: Mutex<Option<Arc<Tunnel>>>,
    /// The session being opened, at most one, which every dial waiting for
    /// a session shares. It runs as a task of its own, so a dial that gives
    /// up leaves it to the next instead of a second session starting: a
    /// server without `duplicate-cn` drops a client's older session when a
    /// newer one connects.
    opening: tokio::sync::Mutex<Option<Opening>>,
    /// Stops the session being opened when the node closes.
    abort_opening: Mutex<Option<AbortHandle>>,
}

/// Why a node with these options cannot connect, judged from the options
/// alone: the file they name is read when a session opens, so what it says
/// fails that session's dials instead.
pub(crate) fn unsupported_option(options: &JsonValue) -> Option<String> {
    node(options).err()
}

/// Where `config` points: an absolute path, or one under the home directory
/// written `~/…`, so one profile serves machines that keep the file in the
/// same place under their homes.
fn config_path(config: &str) -> Result<PathBuf, String> {
    if config.contains('\n') {
        return Err("`config` is the path of a .ovpn file, not its text".into());
    }
    let path = match config
        .strip_prefix("~/")
        .or_else(|| config.strip_prefix("~\\"))
    {
        Some(rest) => std::env::home_dir()
            .ok_or("no home directory to resolve `~/` in `config`")?
            .join(rest),
        None => PathBuf::from(config),
    };
    if !path.is_absolute() {
        return Err("`config` must be an absolute path or start with ~/".into());
    }
    Ok(path)
}

fn node(options: &JsonValue) -> Result<Arc<Node>, String> {
    let config = option_string(options, &["config"])
        .ok_or("an OpenVPN node names its .ovpn file in `config`")?;
    Ok(Arc::new(Node {
        path: config_path(&config)?,
        credentials: proxy_auth(options).map(|auth| Credentials {
            username: auth.username,
            password: auth.password,
        }),
    }))
}

impl Node {
    fn setup(&self, text: &str) -> Result<Setup, String> {
        let config = config::parse(text)?;
        if config.auth_user_pass && self.credentials.is_none() {
            return Err("the OpenVPN server wants a username and password".into());
        }
        let tls = tls_config(&config)?;
        Ok(Setup { config, tls })
    }
}

impl OpenVpnConnector {
    pub(crate) fn new(options: &JsonValue) -> Self {
        Self {
            node: node(options),
            dialer: Dialer::from_options(options),
            // The tunnel carries IP, so UDP goes through unless the node says
            // otherwise.
            udp: option_bool(options, &["udp"]).unwrap_or(true),
            current: Mutex::new(None),
            opening: tokio::sync::Mutex::new(None),
            abort_opening: Mutex::new(None),
        }
    }

    fn current(&self) -> Option<Arc<Tunnel>> {
        self.current
            .lock()
            .expect("OpenVPN tunnel")
            .as_ref()
            .filter(|tunnel| tunnel.is_open())
            .cloned()
    }

    /// The session: the one up, else the one being opened, else a new one.
    async fn tunnel(&self, egress: &EgressRuntime) -> Result<Arc<Tunnel>, OutboundError> {
        let node = self
            .node
            .as_ref()
            .map_err(|error| OutboundError::new(OutboundStage::Config, error.clone()))?;
        if let Some(tunnel) = self.current() {
            return Ok(tunnel);
        }
        let mut opening = self.opening.lock().await;
        if let Some(tunnel) = self.current() {
            return Ok(tunnel);
        }
        let open = opening.get_or_insert_with(|| {
            let open = tokio::spawn(open_session(
                Arc::clone(node),
                self.dialer.clone(),
                egress.clone(),
            ));
            *self.abort_opening.lock().expect("OpenVPN opening") = Some(open.abort_handle());
            open
        });
        let opened = open.await;
        *opening = None;
        self.abort_opening.lock().expect("OpenVPN opening").take();
        let tunnel = opened.unwrap_or_else(|error| {
            Err(OutboundError::new(
                OutboundStage::HopConnect,
                format!("the OpenVPN session stopped opening: {error}"),
            ))
        })?;
        *self.current.lock().expect("OpenVPN tunnel") = Some(Arc::clone(&tunnel));
        Ok(tunnel)
    }

    fn close(&self) {
        if let Some(open) = self.abort_opening.lock().expect("OpenVPN opening").take() {
            open.abort();
        }
        if let Some(tunnel) = self.current.lock().expect("OpenVPN tunnel").take() {
            tunnel.close();
        }
    }
}

/// Opens a session: reads the node's file, then tries each remote in turn
/// (shuffled with `remote-random`) until one comes up. A refusal of the
/// credentials ends the attempt; another remote would refuse them too.
async fn open_session(
    node: Arc<Node>,
    dialer: Dialer,
    egress: EgressRuntime,
) -> Result<Arc<Tunnel>, OutboundError> {
    // Off the executor: opening the file can wait on the user, as while
    // macOS asks whether Egrio may read the folder that holds it.
    let path = node.path.clone();
    let setup = tokio::task::spawn_blocking(move || std::fs::read_to_string(path))
        .await
        .map_err(io::Error::other)
        .and_then(|text| text)
        .map_err(|error| format!("cannot read {}: {error}", node.path.display()))
        .and_then(|text| node.setup(&text))
        .map_err(|error| OutboundError::new(OutboundStage::Config, error))?;
    let mut remotes = setup.config.remotes.clone();
    if setup.config.remote_random {
        for index in (1..remotes.len()).rev() {
            remotes.swap(index, rand::random_range(0..=index));
        }
    }
    let mut failure = None;
    for remote in &remotes {
        match tunnel::open(
            &egress,
            &dialer,
            remote,
            &setup.config,
            setup.tls.clone(),
            node.credentials.clone(),
        )
        .await
        {
            Ok(tunnel) => return Ok(tunnel),
            Err(error) if error.stage == OutboundStage::HopAuth => return Err(error),
            Err(error) => failure = Some(error),
        }
    }
    Err(failure.unwrap_or_else(|| {
        OutboundError::new(OutboundStage::Config, "the configuration has no remote")
    }))
}

impl Drop for OpenVpnConnector {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for OpenVpnConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenVpnConnector")
            .field("config", &self.node.as_ref().map(|node| &node.path))
            .finish_non_exhaustive()
    }
}

/// Where `target` is, through `tunnel`.
async fn resolve(
    tunnel: &Tunnel,
    egress: &EgressRuntime,
    target: &ConnectTarget,
) -> Result<SocketAddr, OutboundError> {
    if let Some(ip) = target.ip() {
        return Ok(SocketAddr::new(ip, target.port));
    }
    let unresolved = |reason: String| {
        OutboundError::new(
            OutboundStage::TargetResolve,
            format!(
                "{} did not resolve through the tunnel: {reason}",
                target.host
            ),
        )
    };
    if tunnel.pushed.dns.is_empty() {
        let addresses = egress
            .lookup_host(&target.host, target.port)
            .await
            .map_err(unresolved)?;
        return addresses
            .into_iter()
            .find(|address| tunnel.reaches(address.ip()))
            .ok_or_else(|| unresolved("no address the tunnel reaches".into()));
    }
    let mut failure = String::from("no DNS server answered");
    for &server in &tunnel.pushed.dns {
        if !tunnel.reaches(server) {
            continue;
        }
        for kind in [RecordType::A, RecordType::AAAA] {
            match query(tunnel, SocketAddr::new(server, 53), &target.host, kind).await {
                Ok(addresses) => {
                    if let Some(ip) = addresses.into_iter().find(|ip| tunnel.reaches(*ip)) {
                        return Ok(SocketAddr::new(ip, target.port));
                    }
                }
                Err(reason) => failure = reason,
            }
        }
    }
    Err(unresolved(failure))
}

/// One DNS question to `server` through the tunnel.
async fn query(
    tunnel: &Tunnel,
    server: SocketAddr,
    host: &str,
    kind: RecordType,
) -> Result<Vec<std::net::IpAddr>, String> {
    let request = wire::query(host, kind)?;
    let mut port = tunnel.udp.open().map_err(|error| error.to_string())?;
    let packet = tunnel
        .addresses
        .udp_packet(port.port(), server, &wire::encode(&request)?)
        .map_err(|error| error.to_string())?;
    tunnel.send(packet).map_err(|error| error.to_string())?;
    let answer = tokio::time::timeout(DNS_TIMEOUT, async {
        loop {
            let (from, payload) = port.recv().await.ok_or("the tunnel closed")?;
            if from != server {
                continue;
            }
            let Ok(answer) = wire::decode(&payload) else {
                continue;
            };
            if wire::validate_response(&request, &answer).is_ok() {
                return Ok::<_, String>(answer);
            }
        }
    })
    .await
    .map_err(|_| format!("{server} did not answer"))??;
    wire::addresses(&answer)
}

impl OutboundConnector for OpenVpnConnector {
    fn connect_stream<'a>(
        &'a self,
        egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            let tunnel = self.tunnel(egress).await?;
            let peer = resolve(&tunnel, egress, target).await?;
            let mut stream = tunnel.connect(peer).await.at(OutboundStage::Target)?;
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
            let tunnel = self.tunnel(egress).await?;
            let port = tunnel.udp.open().at(OutboundStage::Local)?;
            Ok(OutboundDatagramTransport {
                sender: Box::new(DatagramSender {
                    tunnel,
                    egress: egress.clone(),
                    port: port.port(),
                }),
                receiver: Box::new(DatagramReceiver(port)),
            })
        })
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn udp_enabled(&self) -> bool {
        self.udp
    }

    /// A session on the old network may be stranded; the next dial opens
    /// one on the new.
    fn network_changed(&self, _change: &crate::egress::NetworkChange, _egress: &EgressRuntime) {
        self.close();
    }

    /// Every flow through the node goes through its one session.
    fn carrier_runtime(&self) -> Option<tokio::runtime::Id> {
        self.current().map(|tunnel| tunnel.runtime)
    }
}

struct DatagramSender {
    tunnel: Arc<Tunnel>,
    egress: EgressRuntime,
    port: u16,
}

impl OutboundDatagramSender for DatagramSender {
    fn send_cancellation(&self) -> crate::outbound::DatagramSendCancellation {
        crate::outbound::DatagramSendCancellation::AtomicDatagram
    }

    fn send<'a>(&'a self, target: &'a ConnectTarget, payload: &'a [u8]) -> DatagramFuture<'a, ()> {
        Box::pin(async move {
            let to = resolve(&self.tunnel, &self.egress, target)
                .await
                .map_err(|error| DatagramError::Rejected(error.to_string()))?;
            let packet = self
                .tunnel
                .addresses
                .udp_packet(self.port, to, payload)
                .map_err(|error| DatagramError::Rejected(error.to_string()))?;
            self.tunnel.send(packet).map_err(DatagramError::Carrier)
        })
    }
}

struct DatagramReceiver(UdpPort);

impl OutboundDatagramReceiver for DatagramReceiver {
    fn recv(&mut self) -> DatagramFuture<'_, Option<(ConnectTarget, Vec<u8>)>> {
        Box::pin(async move {
            Ok(self.0.recv().await.map(|(from, payload)| {
                (
                    ConnectTarget {
                        host: from.ip().to_string(),
                        port: from.port(),
                    },
                    payload,
                )
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_names_a_file_by_an_absolute_or_home_path() {
        let home = std::env::home_dir().expect("a home directory");
        assert_eq!(
            config_path("~/vpn/office.ovpn").unwrap(),
            home.join("vpn/office.ovpn")
        );
        let absolute = if cfg!(windows) {
            r"C:\vpn\office.ovpn"
        } else {
            "/etc/vpn/office.ovpn"
        };
        assert_eq!(config_path(absolute).unwrap(), PathBuf::from(absolute));
        assert!(config_path("vpn/office.ovpn")
            .unwrap_err()
            .contains("absolute"));
        assert!(config_path("client\nremote 192.0.2.1")
            .unwrap_err()
            .contains("not its text"));
        assert_eq!(
            unsupported_option(&serde_json::json!({ "config": absolute })),
            None,
            "the file is read when a session opens, not with the options"
        );
    }
}
