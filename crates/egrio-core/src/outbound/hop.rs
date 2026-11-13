//! Chained nodes. A node whose `dialer-proxy` names another outbound — a
//! node or a policy group — reaches its own server through that outbound
//! instead of from this host: the hop is asked for a stream (or datagrams)
//! to the node's server, and the node's protocol runs over it unchanged. A
//! node's UDP takes the hop's datagrams ([`chained_datagrams`]), which only
//! a hop that relays UDP has.
//!
//! The name resolves when the node dials, through the policy groups and their
//! state as a routed dial's outbound does, so a group's selection and health
//! decide the hop of each new connection. A hop that resolves to DIRECT is no
//! hop: the node dials its server from this host. A hop may be chained
//! itself, up to [`MAX_HOPS`] hops; a loop, which a group can close only when
//! it resolves, ends there before any socket opens.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::egress::EgressRuntime;
use crate::outbound::{
    BoxedOutboundStream, OutboundConnector, OutboundDatagramTransport, OutboundError,
    OutboundStage, OutboundTable,
};
use crate::policy_group::{now_unix, resolve_outbound_name, CompiledPolicyGroup, GroupStateTable};
use crate::profile::{dialer_proxy, ProxyNode, RuntimeProfile};
use crate::target::ConnectTarget;

mod datagrams;
#[cfg(all(test, feature = "server"))]
mod udp_tests;

pub(crate) use datagrams::{chained_datagrams, held_until_closed, DatagramCodec};

/// The most hops one dial goes through.
const MAX_HOPS: u8 = 8;

/// A snapshot's outbounds as a chained node's dial reaches them. The
/// snapshot holds it; its egress refers to it weakly, since connectors keep
/// egress clones in the tasks they start.
#[derive(Debug)]
pub(crate) struct Hops {
    outbounds: Arc<OutboundTable>,
    groups: Arc<HashMap<String, CompiledPolicyGroup>>,
    group_state: GroupStateTable,
}

impl Hops {
    pub(crate) fn new(
        outbounds: Arc<OutboundTable>,
        groups: Arc<HashMap<String, CompiledPolicyGroup>>,
        group_state: GroupStateTable,
    ) -> Self {
        Self {
            outbounds,
            groups,
            group_state,
        }
    }
}

/// How a node reaches its own server: from this host, or through the
/// outbound its `dialer-proxy` names.
#[derive(Debug, Clone, Default)]
pub(crate) struct Dialer {
    via: Option<String>,
}

impl Dialer {
    /// The node's `dialer-proxy`, from its options.
    pub(crate) fn from_options(options: &JsonValue) -> Self {
        Self {
            via: dialer_proxy(options).map(str::to_owned),
        }
    }

    /// Whether the node names a `dialer-proxy`, whatever it resolves to.
    pub(crate) fn is_chained(&self) -> bool {
        self.via.is_some()
    }

    /// The hop a dial to `server` goes through now; `None` dials from this
    /// host.
    pub(crate) fn hop(
        &self,
        egress: &EgressRuntime,
        server: &ConnectTarget,
    ) -> Result<Option<Hop>, OutboundError> {
        let Some(via) = &self.via else {
            return Ok(None);
        };
        if egress.hop_depth() >= MAX_HOPS {
            return Err(OutboundError::new(
                OutboundStage::Config,
                format!("the dialer-proxy chain through '{via}' is longer than {MAX_HOPS} hops"),
            ));
        }
        let hops = egress.hops().ok_or_else(|| {
            OutboundError::new(
                OutboundStage::Local,
                format!("dialer-proxy '{via}': the profile's outbounds are retired"),
            )
        })?;
        let resolved = resolve_outbound_name(
            &hops.groups,
            &hops.outbounds,
            &hops.group_state,
            via,
            server,
            now_unix(),
        )
        .and_then(|name| Some((Arc::clone(hops.outbounds.get(&name)?), name)));
        let Some((connector, name)) = resolved else {
            return Err(OutboundError::new(
                OutboundStage::Config,
                format!("dialer-proxy '{via}' resolves to no outbound"),
            ));
        };
        if connector.is_direct() {
            return Ok(None);
        }
        Ok(Some(Hop {
            name,
            connector,
            egress: egress.one_hop_on(),
        }))
    }
}

/// The outbound one dial of a chained node goes through.
pub(crate) struct Hop {
    name: String,
    connector: Arc<dyn OutboundConnector>,
    egress: EgressRuntime,
}

impl Hop {
    /// A stream to the node's server through the hop.
    pub(crate) async fn stream(
        &self,
        server: &ConnectTarget,
    ) -> Result<BoxedOutboundStream, OutboundError> {
        self.connector
            .connect_stream(&self.egress, server, &[])
            .await
            .map_err(|error| self.carried(error))
    }

    /// Datagrams to and from the node's server through the hop.
    pub(crate) async fn datagrams(
        &self,
        server: &ConnectTarget,
    ) -> Result<OutboundDatagramTransport, OutboundError> {
        if !self.connector.supports_udp() {
            return Err(OutboundError::new(
                OutboundStage::Config,
                format!("dialer-proxy '{}' does not relay UDP", self.name),
            ));
        }
        self.connector
            .connect_datagram(&self.egress, server)
            .await
            .map_err(|error| self.carried(error))
    }

    /// The hop's failure as the chained node's: whatever kept the hop from
    /// reaching the node's server kept the node from it.
    fn carried(&self, error: OutboundError) -> OutboundError {
        let stage = match error.stage {
            OutboundStage::Config | OutboundStage::Local => error.stage,
            OutboundStage::TargetResolve => OutboundStage::HopResolve,
            _ => OutboundStage::HopConnect,
        };
        OutboundError::new(
            stage,
            format!("through dialer-proxy '{}': {}", self.name, error.message),
        )
    }
}

/// Why `proxy`'s `dialer-proxy` cannot carry it, if it cannot: a name that
/// is no outbound of the profile, or a chain of nodes that loops or reaches
/// a node the Core cannot dial. A chain through a policy group is judged when
/// it is dialed.
pub(crate) fn chain_issue(profile: &RuntimeProfile, proxy: &ProxyNode) -> Option<String> {
    let mut path = vec![proxy.name.as_str()];
    let mut node = proxy;
    while let Some(via) = node.dialer_proxy() {
        if via == "DIRECT"
            || via == "direct"
            || profile.groups.iter().any(|group| group.name == via)
        {
            return None;
        }
        let Some(next) = profile.proxies.iter().find(|proxy| proxy.name == via) else {
            return Some(format!(
                "dialer-proxy '{via}' is not a node or policy group of the profile"
            ));
        };
        if path.contains(&via) {
            return Some(format!("the dialer-proxy chain loops back to '{via}'"));
        }
        if let Some(issue) = crate::runtime::node_issue(next) {
            return Some(format!("dialer-proxy '{via}' cannot be used: {issue}"));
        }
        path.push(via);
        node = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Mutex;

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::profile::{PolicyGroup, PolicyGroupKind, ProxyProtocol, RuntimeProfile};
    use crate::runtime::{open_outbound_connection, NativeCoreRuntime};
    use crate::tcp_flow::TcpFlowFailure;

    use super::*;

    /// An HTTP CONNECT proxy that relays each tunnel and records the
    /// authority it was asked for.
    async fn connect_proxy() -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&asked);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let (header, rest) = crate::protocols::http::read_http_header(&mut client)
                        .await
                        .unwrap();
                    let authority = header.split_whitespace().nth(1).unwrap().to_owned();
                    log.lock().unwrap().push(authority.clone());
                    let mut upstream = TcpStream::connect(&authority).await.unwrap();
                    client
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    upstream.write_all(&rest).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (port, asked)
    }

    async fn echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        address
    }

    fn node(name: &str, port: u16, via: Option<&str>) -> ProxyNode {
        ProxyNode {
            id: name.into(),
            name: name.into(),
            protocol: ProxyProtocol::Http,
            server: Some("127.0.0.1".into()),
            port: Some(port),
            options: via.map_or(json!({}), |via| json!({ "dialer-proxy": via })),
        }
    }

    fn select(name: &str, members: &[&str]) -> PolicyGroup {
        PolicyGroup {
            id: name.into(),
            name: name.into(),
            kind: PolicyGroupKind::Select,
            members: members.iter().map(|member| member.to_string()).collect(),
            interval_seconds: None,
            test_url: None,
            selected: None,
        }
    }

    fn target(address: SocketAddr) -> ConnectTarget {
        ConnectTarget {
            host: address.ip().to_string(),
            port: address.port(),
        }
    }

    async fn round_trip(runtime: &NativeCoreRuntime, to: SocketAddr, outbound: &str) {
        let (mut stream, _) = open_outbound_connection(runtime, &target(to), outbound, b"")
            .await
            .expect("dial");
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    }

    #[tokio::test]
    async fn a_chained_node_reaches_its_server_through_its_dialer_proxy() {
        let origin = echo().await;
        let (entry, entry_asked) = connect_proxy().await;
        let (exit, exit_asked) = connect_proxy().await;
        let mut profile = RuntimeProfile::new("chain");
        profile.proxies = vec![node("entry", entry, None), node("exit", exit, Some("hop"))];
        profile.groups = vec![select("hop", &["entry"])];
        let runtime = NativeCoreRuntime::compile(&profile);

        round_trip(&runtime, origin, "exit").await;
        assert_eq!(*entry_asked.lock().unwrap(), [format!("127.0.0.1:{exit}")]);
        assert_eq!(*exit_asked.lock().unwrap(), [origin.to_string()]);
    }

    #[tokio::test]
    async fn a_dialer_proxy_that_resolves_to_direct_dials_from_this_host() {
        let origin = echo().await;
        let (entry, entry_asked) = connect_proxy().await;
        let (exit, exit_asked) = connect_proxy().await;
        let mut profile = RuntimeProfile::new("chain");
        profile.proxies = vec![node("entry", entry, None), node("exit", exit, Some("hop"))];
        profile.groups = vec![select("hop", &["DIRECT", "entry"])];
        let runtime = NativeCoreRuntime::compile(&profile);

        round_trip(&runtime, origin, "exit").await;
        assert!(entry_asked.lock().unwrap().is_empty());
        assert_eq!(*exit_asked.lock().unwrap(), [origin.to_string()]);
    }

    #[tokio::test]
    async fn a_chain_a_group_loops_ends_before_any_socket_opens() {
        let origin = echo().await;
        let (exit, exit_asked) = connect_proxy().await;
        let mut profile = RuntimeProfile::new("chain");
        profile.proxies = vec![node("exit", exit, Some("hop"))];
        profile.groups = vec![select("hop", &["exit"])];
        let runtime = NativeCoreRuntime::compile(&profile);

        let Err(TcpFlowFailure::Outbound { stage, message }) =
            open_outbound_connection(&runtime, &target(origin), "exit", b"").await
        else {
            panic!("a looping chain must not connect");
        };
        assert_eq!(stage, OutboundStage::Config);
        assert!(message.contains("longer than 8 hops"), "{message}");
        assert!(exit_asked.lock().unwrap().is_empty());
    }
}
