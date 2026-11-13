//! Physical DNS resolution: bounded shared cache, request-owned single-flight,
//! staggered server fallback, and UDP truncation recovery over TCP.

#[cfg(test)]
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::{lookup_host as system_lookup_host, UdpSocket};
use tokio::time::{sleep_until, timeout, timeout_at, Duration, Instant};

use super::pending::Pending;
use super::{default_udp_bind_ip_for_host, EgressRuntime, EgressSocketContext};
use crate::dns::{
    cache::{DnsCache, QuerySharing},
    transport::exchange_tcp,
    wire,
};
use crate::target::{literal_socket_addr, ConnectTarget};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;

#[cfg(test)]
pub(super) const DNS_CLASS_IN: u16 = 1;
pub(super) const DNS_TYPE_A: u16 = 1;
pub(super) const DNS_TYPE_AAAA: u16 = 28;
const DNS_QUERY_BUDGET: Duration = Duration::from_secs(5);
const SERVER_STAGGER: Duration = Duration::from_millis(250);
const SERVER_BUDGET: Duration = Duration::from_secs(2);
const MAX_PARALLEL_SERVERS: usize = 4;
const MAX_REPORTED_ERRORS: usize = 16;
const MAX_DNS_MESSAGE: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    host: String,
    qtype: u16,
}

#[derive(Debug, Default)]
pub(super) struct Resolver {
    cache: DnsCache<CacheKey>,
}
impl Resolver {
    async fn resolve(
        &self,
        egress: &EgressRuntime,
        host: &str,
        qtype: u16,
    ) -> Result<Message, String> {
        let key = CacheKey {
            host: crate::dns::resolver::normalize_domain(host),
            qtype,
        };
        let request = wire::query(&key.host, RecordType::from(qtype))?;
        self.cache
            .resolve(
                key,
                request.id,
                Instant::now() + DNS_QUERY_BUDGET,
                QuerySharing::Shared,
                query_servers(egress, request),
            )
            .await
    }
}

impl EgressRuntime {
    /// DNS families remain independently ready so the TCP scheduler can dial
    /// an early result while keeping the other family's resolution alive.
    pub(crate) fn resolve_candidates<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        purpose: crate::dns::service::QueryPurpose,
    ) -> Result<Pending<'a, Result<Vec<SocketAddr>, String>>, String> {
        let target = ConnectTarget {
            host: host.into(),
            port,
        };
        self.validate_outbound_target(&target, true)
            .map_err(|reason| format!("target {} rejected: {reason}", target.authority()))?;
        let mut pending = Pending::new();
        // An absolute name's trailing dot does not make an IP literal a name.
        if let Some(address) = literal_socket_addr(host.trim_end_matches('.'), port) {
            pending.push(async move { Ok(vec![address]) });
        } else if crate::dns::resolver::is_localhost_name(host) {
            // RFC 6761 section 6.3: the loopback address, asking no one.
            let ipv6 = self.ipv6_enabled();
            pending.push(async move {
                let mut addresses = vec![SocketAddr::from((Ipv4Addr::LOCALHOST, port))];
                if ipv6 {
                    addresses.push(SocketAddr::from((Ipv6Addr::LOCALHOST, port)));
                }
                Ok(addresses)
            });
        } else if let Some(service) = self.dns_service()? {
            // RFC 8305 section 3: AAAA first, A right after it.
            for ipv6 in [true, false] {
                if ipv6 && !service.ipv6_enabled() {
                    continue;
                }
                let service = service.clone();
                let context = self.dns_context.clone();
                pending.push(async move {
                    service
                        .resolve_family(host, port, ipv6, purpose, context)
                        .await
                });
            }
        } else if self.dns_servers().is_empty() {
            pending.push(async move {
                let addresses = timeout(DNS_QUERY_BUDGET, system_lookup_host((host, port)))
                    .await
                    .map_err(|_| format!("system DNS resolution for {host} timed out after 5s"))?
                    .map_err(|error| format!("failed to resolve {host}: {error}"))?;
                Ok(addresses
                    .filter(|address| self.ipv6_enabled() || address.is_ipv4())
                    .collect())
            });
        } else {
            for qtype in [DNS_TYPE_AAAA, DNS_TYPE_A] {
                if qtype == DNS_TYPE_AAAA && !self.ipv6_enabled() {
                    continue;
                }
                pending.push(async move {
                    self.resolver
                        .resolve(self, host, qtype)
                        .await
                        .and_then(|message| {
                            wire::addresses(&message).map(|ips| {
                                ips.into_iter()
                                    .map(|ip| SocketAddr::new(ip, port))
                                    .collect()
                            })
                        })
                });
            }
        }
        Ok(match self.lookup_clock.clone() {
            Some(clock) => pending.inspected(move |result: &Result<Vec<SocketAddr>, String>| {
                if result.as_ref().is_ok_and(|addresses| !addresses.is_empty()) {
                    clock.answered();
                }
            }),
            None => pending,
        })
    }

    /// The address a proxy is handed for a name the hosts map: its first
    /// IPv4 address, else its first IPv6 one.
    pub(crate) fn hosts_target(&self, target: &ConnectTarget) -> Option<ConnectTarget> {
        if target.ip().is_some() {
            return None;
        }
        let addresses = self.dns_service().ok().flatten()?.hosts(&target.host)?;
        let address = addresses
            .iter()
            .find(|address| address.is_ipv4())
            .or_else(|| addresses.first())?;
        Some(ConnectTarget {
            host: address.to_string(),
            port: target.port,
        })
    }

    /// Complete resolution for consumers that select a single UDP endpoint.
    /// Collect both families under one budget, retaining any successful family
    /// when the other fails. IPv4 stays first regardless of DNS arrival order;
    /// TCP uses resolve_candidates directly and does not wait for this batch.
    pub(crate) async fn lookup_host(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, String> {
        let mut pending =
            self.resolve_candidates(host, port, crate::dns::service::QueryPurpose::ProxyEndpoint)?;
        let mut addresses = Vec::new();
        let mut errors = Vec::new();
        let deadline = Instant::now() + DNS_QUERY_BUDGET;
        loop {
            match timeout_at(deadline, pending.next()).await {
                Ok(Some(Ok(result))) => {
                    for address in result {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                }
                Ok(Some(Err(error))) => errors.push(error),
                Ok(None) => break,
                Err(_) => {
                    errors.push("DNS resolution budget expired".into());
                    break;
                }
            }
        }
        if !addresses.is_empty() {
            // Stable sort preserves each family's resolver order.
            addresses.sort_by_key(SocketAddr::is_ipv6);
            Ok(addresses)
        } else {
            Err(format!("failed to resolve {host}: {}", errors.join("; ")))
        }
    }

    /// A DNS A request must not wait for AAAA, or vice versa. Callers that
    /// actually need one record family use this rather than flattening both.
    pub(crate) async fn lookup_host_record(
        &self,
        host: &str,
        port: u16,
        ipv6: bool,
    ) -> Result<Vec<SocketAddr>, String> {
        if ipv6 && !self.ipv6_enabled() {
            return Ok(Vec::new());
        }
        if self.dns_servers().is_empty() || literal_socket_addr(host, port).is_some() {
            return self.lookup_host(host, port).await.map(|addresses| {
                addresses
                    .into_iter()
                    .filter(|address| address.is_ipv6() == ipv6)
                    .collect()
            });
        }
        let reply = self
            .resolver
            .resolve(self, host, if ipv6 { DNS_TYPE_AAAA } else { DNS_TYPE_A })
            .await?;
        Ok(wire::addresses(&reply)?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect())
    }
}

async fn query_servers(egress: &EgressRuntime, request: Message) -> Result<Message, String> {
    let deadline = Instant::now() + DNS_QUERY_BUDGET;
    let mut servers = egress.dns_servers().into_iter();
    let mut pending = Pending::new();
    let mut next_server = Some(Instant::now());
    let mut errors = Vec::new();
    let mut server_failure = None;
    loop {
        if pending.len() < MAX_PARALLEL_SERVERS
            && next_server.is_some_and(|when| when <= Instant::now())
        {
            if let Some(server) = servers.next() {
                let server_deadline = deadline.min(Instant::now() + SERVER_BUDGET);
                let request = &request;
                pending.push(async move {
                    query_server(egress, request, server, server_deadline)
                        .await
                        .map_err(|error| format!("{server}: {error}"))
                });
                next_server = Some(Instant::now() + SERVER_STAGGER);
            } else {
                next_server = None;
            }
        }
        if pending.is_empty() && next_server.is_none() {
            break;
        }
        tokio::select! {
            result = pending.next(), if !pending.is_empty() => {
                match result.expect("pending DNS query") {
                    Ok(answer) if answer.response_code == ResponseCode::ServFail => server_failure = Some(answer),
                    Ok(answer) => return Ok(answer),
                    Err(error) => if errors.len() < MAX_REPORTED_ERRORS { errors.push(error); },
                }
                if pending.is_empty() && next_server.is_some() {
                    next_server = Some(Instant::now());
                }
            }
            _ = sleep_until(next_server.unwrap_or(deadline)), if next_server.is_some() && pending.len() < MAX_PARALLEL_SERVERS => {},
            _ = sleep_until(deadline) => {
                errors.push("DNS query budget expired".into());
                break;
            }
        }
    }
    server_failure.ok_or_else(|| errors.join("; "))
}

async fn query_server(
    egress: &EgressRuntime,
    request: &Message,
    server: SocketAddr,
    deadline: Instant,
) -> Result<Message, String> {
    egress
        .validate_outbound_target(
            &ConnectTarget {
                host: server.ip().to_string(),
                port: server.port(),
            },
            true,
        )
        .map_err(|reason| format!("DNS server rejected: {reason}"))?;
    let query = wire::encode(request)?;
    let socket = UdpSocket::bind(SocketAddr::new(
        default_udp_bind_ip_for_host(&server.ip().to_string()),
        0,
    ))
    .await
    .map_err(|error| error.to_string())?;
    egress.guard_egress_socket(
        &socket,
        EgressSocketContext::for_remote(server.ip()),
        "egress DNS socket",
    )?;
    timeout_at(deadline, async {
        socket
            .connect(server)
            .await
            .map_err(|error| error.to_string())?;
        socket
            .send(&query)
            .await
            .map_err(|error| error.to_string())?;
        let mut bytes = vec![0; MAX_DNS_MESSAGE];
        let response = loop {
            let length = socket
                .recv(&mut bytes)
                .await
                .map_err(|error| error.to_string())?;
            if let Ok(response) = wire::decode(&bytes[..length]) {
                if wire::validate_response(request, &response).is_ok() {
                    break response;
                }
            }
        };
        if response.truncation {
            let (stream, _) = egress
                .connect_tcp_endpoint(server, deadline.saturating_duration_since(Instant::now()))
                .await
                .map_err(|error| error.to_string())?;
            let mut stream: crate::outbound::BoxedOutboundStream = Box::new(stream);
            exchange_tcp(&mut stream, request).await
        } else {
            Ok(response)
        }
    })
    .await
    .map_err(|_| "DNS query timed out".to_string())?
}

#[cfg(test)]
fn word(payload: &[u8], offset: usize) -> Result<u16, String> {
    let bytes = payload
        .get(offset..offset + 2)
        .ok_or("DNS response is truncated")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
fn build_query(host: &str, qtype: u16) -> Result<(u16, Vec<u8>), String> {
    let request = wire::query(host, RecordType::from(qtype))?;
    Ok((request.id, wire::encode(&request)?))
}
#[cfg(test)]
struct TestAnswer {
    addresses: Vec<IpAddr>,
    ttl: Duration,
    response_code: ResponseCode,
}
#[cfg(test)]
enum WireAnswer {
    Complete(TestAnswer),
    Truncated,
}
#[cfg(test)]
fn parse_response(payload: &[u8], id: u16, host: &str, qtype: u16) -> Result<WireAnswer, String> {
    let mut request = wire::query(host, RecordType::from(qtype))?;
    request.metadata.id = id;
    let response = wire::decode(payload)?;
    wire::validate_response(&request, &response)?;
    if response.truncation {
        Ok(WireAnswer::Truncated)
    } else {
        Ok(WireAnswer::Complete(TestAnswer {
            addresses: if response.response_code == ResponseCode::NoError {
                wire::addresses(&response)?
            } else {
                Vec::new()
            },
            ttl: wire::positive_ttl(&response).unwrap_or(Duration::ZERO),
            response_code: response.response_code,
        }))
    }
}

#[cfg(test)]
mod tests;
