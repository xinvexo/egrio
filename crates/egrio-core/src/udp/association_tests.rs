use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use super::*;
use crate::dns::config::{DnsMode, DnsRoute, DnsTransport, DnsUpstream};
use crate::profile::{
    ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile, TrafficPolicyMode,
};
use crate::NativeCoreDevice;

fn target(host: &str, port: u16) -> ConnectTarget {
    ConnectTarget {
        host: host.into(),
        port,
    }
}

async fn dns_stub() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let (address, task, _) = dns_stub_with_ttl(60).await;
    (address, task)
}

async fn dns_stub_with_ttl(
    ttl: u32,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<std::sync::atomic::AtomicUsize>,
) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = queries.clone();
    let task = tokio::spawn(async move {
        let mut data = [0; 4096];
        loop {
            let (len, peer) = socket.recv_from(&mut data).await.unwrap();
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut end = 12;
            while data[end] != 0 {
                end += 1 + data[end] as usize;
            }
            end += 5;
            assert!(end <= len);
            let missing = data[12] == 3 && &data[13..16] == b"bad";
            let v6_only = data[12] == 2 && &data[13..15] == b"v6";
            let is_a = !missing && !v6_only && data[end - 4..end - 2] == [0, 1];
            let is_aaaa = !missing && v6_only && data[end - 4..end - 2] == [0, 28];
            let mut answer = data[..2].to_vec();
            answer.extend_from_slice(&[
                0x81,
                if missing { 0x83 } else { 0x80 },
                0,
                1,
                0,
                u8::from(is_a || is_aaaa),
                0,
                0,
                0,
                0,
            ]);
            answer.extend_from_slice(&data[12..end]);
            if is_a {
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
                answer.extend_from_slice(&ttl.to_be_bytes());
                answer.extend_from_slice(&[0, 4, 127, 0, 0, 1]);
            }
            if is_aaaa {
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1]);
                answer.extend_from_slice(&ttl.to_be_bytes());
                answer.extend_from_slice(&[0, 16]);
                answer.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
            }
            socket.send_to(&answer, peer).await.unwrap();
        }
    });
    (address, task, queries)
}

fn configured_profile(dns: SocketAddr) -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("udp-address-bindings");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    profile.dns.nameservers = vec![DnsUpstream {
        transport: DnsTransport::Udp,
        host: dns.ip().to_string(),
        port: dns.port(),
        path: String::new(),
        server_name: None,
        route: Some(DnsRoute::Direct),
    }];
    profile
}

struct ProxyDatagram {
    relay: Arc<UdpSocket>,
    peer: SocketAddr,
    target: ConnectTarget,
    payload: Vec<u8>,
}
impl ProxyDatagram {
    async fn reply(&self, source: ConnectTarget, payload: &[u8]) {
        let mut frame = vec![0, 0, 0];
        frame.extend_from_slice(&source.socks_address().unwrap());
        frame.extend_from_slice(payload);
        socket2::SockRef::from(self.relay.as_ref())
            .set_send_buffer_size(crate::outbound::UDP_DATAGRAM_CAPACITY)
            .unwrap();
        self.relay.send_to(&frame, self.peer).await.unwrap();
    }
}

async fn socks_proxy() -> (
    SocketAddr,
    mpsc::Receiver<ProxyDatagram>,
    mpsc::Receiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = mpsc::channel(16);
    let (closed_tx, closed_rx) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        let mut associations = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut control, _) = accepted.unwrap();
                    let sent = sent.clone();
                    let closed = closed_tx.clone();
                    associations.spawn(async move {
                        let mut greeting = [0; 3];
                        control.read_exact(&mut greeting).await.unwrap();
                        assert_eq!(greeting, [5, 1, 0]);
                        control.write_all(&[5, 0]).await.unwrap();
                        let mut request = [0; 10];
                        control.read_exact(&mut request).await.unwrap();
                        assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
                        let relay = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
                        let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                        reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
                        control.write_all(&reply).await.unwrap();
                        let mut buffer = [0; 65535];
                        let mut probe = [0; 1];
                        loop {
                            tokio::select! {
                                result = control.read(&mut probe) => {
                                    assert_eq!(result.unwrap(), 0);
                                    closed.send(()).await.unwrap();
                                    break;
                                }
                                result = relay.recv_from(&mut buffer) => {
                                    let (len, peer) = result.unwrap();
                                    assert_eq!(&buffer[..3], &[0, 0, 0]);
                                    let (target, used) = crate::target::parse_socks_address(&buffer[3..len]).unwrap();
                                    sent.send(ProxyDatagram {
                                        relay: relay.clone(), peer, target,
                                        payload: buffer[3+used..len].to_vec(),
                                    }).await.unwrap();
                                }
                            }
                        }
                    });
                }
                result = associations.join_next(), if !associations.is_empty() => { result.unwrap().unwrap(); }
            }
        }
    });
    (address, received, closed_rx, task)
}

/// One captured client source, driven the way the packet executor drives
/// TUN UDP: datagrams enter as a named flow and replies are drained by flow.
struct TunFlow {
    runtime: NativeCoreRuntime,
    id: String,
    source: SocketAddr,
}

impl TunFlow {
    fn open(runtime: &NativeCoreRuntime, source: &str) -> Self {
        let source: SocketAddr = source.parse().unwrap();
        Self {
            runtime: runtime.clone(),
            id: format!("tun-test-{source}"),
            source,
        }
    }

    async fn try_send(&self, target: &ConnectTarget, payload: &[u8]) -> Result<bool, String> {
        send_udp_flow_datagram(
            &self.runtime,
            UdpDatagram {
                flow_id: Some(self.id.clone()),
                pump_queue: None,
                inbound: "tun",
                user: None,
                source: self.source,
                target: target.clone(),
                payload: payload.to_vec(),
                process_name: None,
                process_path: None,
            },
        )
        .await
        .map(|outcome| outcome.enqueued)
    }

    async fn send(&self, target: &ConnectTarget, payload: &[u8]) {
        assert!(self.try_send(target, payload).await.unwrap());
    }

    async fn recv_batch(&self, max_datagrams: usize) -> Vec<UdpPendingFlowDatagram> {
        drain_pending_udp_flow_responses_for_prefix(
            &self.runtime,
            Some(&self.id),
            max_datagrams,
            Duration::from_secs(3),
        )
        .await
    }

    fn is_open(&self) -> bool {
        self.runtime.udp_sessions().flow_session_count(&self.id) > 0
    }

    async fn close(&self) {
        close_udp_flow_sessions(&self.runtime, &self.id).unwrap();
        wait_for_released_associations(&self.runtime).await;
    }
}

/// Closing aborts session actors; their association slots return once the
/// runtime drops the aborted tasks.
async fn wait_for_released_associations(runtime: &NativeCoreRuntime) {
    timeout(Duration::from_secs(3), async {
        while runtime.udp_sessions().association_slots.available_permits()
            != UDP_ASSOCIATIONS_GLOBAL
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed UDP sessions release their association slots");
}

async fn close_all(runtime: &NativeCoreRuntime) {
    close_udp_sessions(runtime);
    wait_for_released_associations(runtime).await;
}

/// A fake IP's name resolves, then its identity joins the association the
/// client's real targets use through the same proxy, so a STUN server reached
/// by name and a peer reached by address see one mapping (EIM). A name that
/// resolves to an address another identity there claims gets an association
/// of its own, so each reply still comes back from the address its sender
/// used.
#[tokio::test]
async fn a_fake_ip_shares_the_socks_association_of_real_targets_unless_its_address_is_claimed() {
    let (dns, dns_task) = dns_stub().await;
    let (proxy, mut requests, mut closed, proxy_task) = socks_proxy().await;
    let mut profile = configured_profile(dns);
    profile.proxies.push(ProxyNode {
        id: "socks".into(),
        name: "socks".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some(proxy.ip().to_string()),
        port: Some(proxy.port()),
        options: serde_json::json!({"udp": true}),
    });
    profile.rules = profile
        .rules
        .iter()
        .chain([RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "socks",
            no_resolve: false,
        }])
        .collect();
    let core = NativeCoreDevice::compile(&profile);
    let runtime = core.pinned_runtime();
    let a = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("a.test")
            .unwrap()
            .to_string(),
        443,
    );
    let b = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("b.test")
            .unwrap()
            .to_string(),
        443,
    );
    let flow = TunFlow::open(&runtime, "127.0.0.1:54321");
    let mut sent = HashMap::new();
    // One at a time: `a.test` joins first, so `b.test`, resolving to the
    // same address, is the one with an association of its own.
    for (destination, payload) in [(&a, b"a".as_slice()), (&b, b"b".as_slice())] {
        flow.send(destination, payload).await;
        let request = timeout(Duration::from_secs(3), requests.recv())
            .await
            .unwrap()
            .unwrap();
        sent.insert(request.payload.clone(), request);
    }
    flow.send(&target(&a.host, 444), b"a-other-port").await;
    flow.send(&target("192.0.2.10", 3478), b"real-a").await;
    flow.send(&target("192.0.2.11", 3479), b"real-b").await;
    let large_upload = vec![0xa5; 48 * 1024];
    flow.send(&b, &large_upload).await;
    for _ in 0..4 {
        let request = timeout(Duration::from_secs(3), requests.recv())
            .await
            .unwrap()
            .unwrap();
        sent.insert(request.payload.clone(), request);
    }
    let first = &sent[b"a".as_slice()];
    let second = &sent[b"b".as_slice()];
    assert_eq!(
        first.target,
        target("127.0.0.1", 443),
        "wire target must be prepared numeric address"
    );
    assert_eq!(second.target, first.target);
    assert_eq!(
        sent[large_upload.as_slice()].peer,
        second.peer,
        "large legal SOCKS datagrams use the same association"
    );
    assert_eq!(
        sent[b"a-other-port".as_slice()].peer,
        first.peer,
        "one virtual address reuses its association across destination ports"
    );
    assert_eq!(
        sent[b"a-other-port".as_slice()].target,
        target("127.0.0.1", 444)
    );
    assert_ne!(
        first.peer, second.peer,
        "a name at an address another identity claims has an association of its own"
    );
    assert_eq!(
        sent[b"real-a".as_slice()].peer,
        sent[b"real-b".as_slice()].peer,
        "real destinations preserve EIM"
    );
    assert_eq!(
        sent[b"real-a".as_slice()].peer,
        first.peer,
        "a fake IP and the real targets share one association (EIM)"
    );
    assert_eq!(core.state_audit().udp_sessions, 1, "one client owner");
    assert_eq!(core.state_audit().udp_session_sockets, 2);
    second.reply(target("127.0.0.1", 443), b"b-reply").await;
    first
        .reply(target("127.0.0.1", 8443), b"a-alternate-port")
        .await;
    first
        .reply(target("192.0.2.99", 5000), b"unknown-peer")
        .await;
    first.reply(target("A.TEST.", 9000), b"domain-source").await;
    sent[b"real-a".as_slice()]
        .reply(target("192.0.2.77", 6000), b"real-eif")
        .await;
    let large_reply = vec![0xd5; 48 * 1024];
    second.reply(target("127.0.0.1", 443), &large_reply).await;
    let mut replies = HashMap::new();
    while replies.len() < 6 {
        let batch = flow.recv_batch(64).await;
        for reply in batch {
            replies.insert(
                reply.payload.clone(),
                target(&reply.source_endpoint.host, reply.source_endpoint.port),
            );
        }
    }
    assert_eq!(replies[b"b-reply".as_slice()], b);
    assert_eq!(
        replies[large_reply.as_slice()],
        b,
        "SOCKS replies larger than old small-buffer profiles remain complete"
    );
    assert_eq!(
        replies[b"a-alternate-port".as_slice()],
        target(&a.host, 8443)
    );
    assert_eq!(
        replies[b"unknown-peer".as_slice()],
        target("192.0.2.99", 5000)
    );
    assert_eq!(replies[b"domain-source".as_slice()], target(&a.host, 9000));
    assert_eq!(replies[b"real-eif".as_slice()], target("192.0.2.77", 6000));
    flow.close().await;
    for _ in 0..2 {
        timeout(Duration::from_secs(3), closed.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(
        runtime.udp_sessions().association_slots.available_permits(),
        UDP_ASSOCIATIONS_GLOBAL
    );
    assert_eq!(core.state_audit().udp_sessions, 0);
    close_all(&runtime).await;
    proxy_task.abort();
    dns_task.abort();
}

#[tokio::test]
async fn direct_virtual_associations_bind_before_send_and_accept_alternate_source_port() {
    let (dns, dns_task) = dns_stub().await;
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let alternate = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let core = NativeCoreDevice::compile(&configured_profile(dns));
    let runtime = core.pinned_runtime();
    let port = server.local_addr().unwrap().port();
    let a = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("a.test")
            .unwrap()
            .to_string(),
        port,
    );
    let b = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("b.test")
            .unwrap()
            .to_string(),
        port,
    );
    let flow = TunFlow::open(&runtime, "127.0.0.1:54322");
    flow.send(&a, b"a").await;
    flow.send(&b, b"b").await;
    let mut peers = HashMap::new();
    for _ in 0..2 {
        let mut buffer = [0; 16];
        let (len, peer) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        peers.insert(buffer[..len].to_vec(), peer);
    }
    assert_ne!(peers[b"a".as_slice()], peers[b"b".as_slice()]);
    server.send_to(b"b", peers[b"b".as_slice()]).await.unwrap();
    alternate
        .send_to(b"a", peers[b"a".as_slice()])
        .await
        .unwrap();
    let mut replies = HashMap::new();
    while replies.len() < 2 {
        let batch = flow.recv_batch(64).await;
        for reply in batch {
            replies.insert(
                reply.payload.clone(),
                target(&reply.source_endpoint.host, reply.source_endpoint.port),
            );
        }
    }
    assert_eq!(replies[b"b".as_slice()], b);
    assert_eq!(
        replies[b"a".as_slice()],
        target(&a.host, alternate.local_addr().unwrap().port())
    );
    close_all(&runtime).await;
    assert_eq!(
        runtime.udp_sessions().association_slots.available_permits(),
        UDP_ASSOCIATIONS_GLOBAL
    );
    dns_task.abort();
}

/// The hole-punch case: a STUN server reached by name and a peer reached by
/// address see the client's one DIRECT socket, so the peer is sent from the
/// mapping STUN reported; the STUN reply comes back from its fake IP.
#[tokio::test]
async fn a_name_and_an_address_share_the_direct_mapping() {
    let (dns, dns_task) = dns_stub().await;
    let stun_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let core = NativeCoreDevice::compile(&configured_profile(dns));
    let runtime = core.pinned_runtime();
    let stun = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("stun.test")
            .unwrap()
            .to_string(),
        stun_server.local_addr().unwrap().port(),
    );
    let flow = TunFlow::open(&runtime, "127.0.0.1:54330");
    let mut buffer = [0; 32];
    flow.send(&stun, b"binding-request").await;
    let (len, mapping) = timeout(Duration::from_secs(3), stun_server.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], b"binding-request");
    flow.send(
        &target("127.0.0.1", peer.local_addr().unwrap().port()),
        b"punch",
    )
    .await;
    let (len, seen) = timeout(Duration::from_secs(3), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], b"punch");
    assert_eq!(seen, mapping, "the peer sees the mapping STUN reported");
    assert_eq!(core.state_audit().udp_session_sockets, 1);
    stun_server
        .send_to(b"binding-response", mapping)
        .await
        .unwrap();
    let replies = flow.recv_batch(1).await;
    assert_eq!(replies[0].source_endpoint, stun);
    close_all(&runtime).await;
    dns_task.abort();
}

#[tokio::test]
async fn association_capacity_is_per_owner_and_global_and_cancel_releases_every_slot() {
    let mut profile = RuntimeProfile::new("udp-association-capacity");
    profile.dns.enabled = true;
    profile.dns.enhanced_mode = DnsMode::FakeIp;
    let core = NativeCoreDevice::compile(&profile);
    let runtime = core.pinned_runtime();
    let targets: Vec<_> = (0..=UDP_ASSOCIATIONS_PER_OWNER)
        .map(|index| {
            target(
                &runtime
                    .fake_dns()
                    .allocate_ipv4(&format!("host-{index}.test"))
                    .unwrap()
                    .to_string(),
                443,
            )
        })
        .collect();
    let first = TunFlow::open(&runtime, "127.0.0.1:55000");
    for address in &targets[..UDP_ASSOCIATIONS_PER_OWNER] {
        first.send(address, b"queued").await;
    }
    let rejected = &targets[UDP_ASSOCIATIONS_PER_OWNER];
    let error = first
        .try_send(&target(&rejected.host, rejected.port), b"not-enqueued")
        .await
        .unwrap_err();
    assert!(error.contains("per-owner association limit"));
    assert!(first.is_open());

    for index in 1..UDP_ASSOCIATIONS_GLOBAL / UDP_ASSOCIATIONS_PER_OWNER {
        let flow = TunFlow::open(
            &runtime,
            &SocketAddr::from((Ipv4Addr::LOCALHOST, 55000 + index as u16)).to_string(),
        );
        for address in &targets[..UDP_ASSOCIATIONS_PER_OWNER] {
            flow.send(address, b"queued").await;
        }
    }
    assert_eq!(
        runtime.udp_sessions().association_slots.available_permits(),
        0
    );
    let overflow = TunFlow::open(&runtime, "127.0.0.1:55200");
    let error = overflow
        .try_send(&target(&targets[0].host, 443), b"not-enqueued")
        .await
        .unwrap_err();
    assert!(error.contains("Core association limit"));
    // Every name still waits to resolve: none has a transport yet, and
    // each holds its slot.
    assert_eq!(core.state_audit().udp_session_sockets, 0);

    // The fruitless sweep stands: a client sending into a table that stays
    // full must not pay one per datagram, since it runs under the lock every
    // capture queue's pump and every inbound face share.
    let swept = runtime
        .udp_sessions()
        .state
        .lock()
        .expect("udp session state")
        .swept_full;
    assert!(swept.is_some(), "the refusal recorded its sweep");
    for _ in 0..4 {
        let again = overflow
            .try_send(&target(&targets[0].host, 443), b"not-enqueued")
            .await
            .unwrap_err();
        assert!(again.contains("Core association limit"));
    }
    assert_eq!(
        runtime
            .udp_sessions()
            .state
            .lock()
            .expect("udp session state")
            .swept_full,
        swept,
        "nothing changed, so no later refusal swept again"
    );

    // No task has been polled: cancellation must still drop every queued
    // packet and slot, with no DNS or socket activity.
    close_all(&runtime).await;
    assert_eq!(
        runtime.udp_sessions().association_slots.available_permits(),
        UDP_ASSOCIATIONS_GLOBAL
    );
    assert_eq!(core.state_audit().udp_sessions, 0);
    assert_eq!(core.state_audit().udp_transport.failures, 0);
}

#[tokio::test]
async fn failed_virtual_target_leaves_owner_and_other_mapping_alive_without_replay() {
    let (dns, dns_task) = dns_stub().await;
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let core = NativeCoreDevice::compile(&configured_profile(dns));
    let runtime = core.pinned_runtime();
    let port = server.local_addr().unwrap().port();
    let bad = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("bad.test")
            .unwrap()
            .to_string(),
        port,
    );
    let good = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("good.test")
            .unwrap()
            .to_string(),
        port,
    );
    let flow = TunFlow::open(&runtime, "127.0.0.1:55300");
    flow.send(&bad, b"dropped-first-bad-packet").await;
    flow.send(&good, b"first-good-packet").await;
    let mut buffer = [0; 64];
    let (len, first_peer) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], b"first-good-packet");
    server
        .send_to(b"first-good-reply", first_peer)
        .await
        .unwrap();
    let replies = flow.recv_batch(1).await;
    assert_eq!(replies[0].source_endpoint.host, good.host);
    drop(replies);
    timeout(Duration::from_secs(3), async {
        while core.state_audit().udp_transport.failures == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(flow.is_open());
    // The good association keeps its slot; the failed one may already have
    // been pruned by the reply drain.
    assert!(runtime.udp_sessions().association_slots.available_permits() < UDP_ASSOCIATIONS_GLOBAL);

    flow.send(&bad, b"new-bad-packet-only").await;
    flow.send(&good, b"second-good-packet").await;
    let (len, second_peer) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], b"second-good-packet");
    assert_eq!(
        first_peer, second_peer,
        "unrelated failure must not replace the good mapping"
    );
    timeout(Duration::from_secs(3), async {
        while core.state_audit().udp_transport.failures < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(flow.is_open());
    assert!(
        timeout(Duration::from_millis(20), server.recv_from(&mut buffer))
            .await
            .is_err(),
        "failed payloads are never retried or replayed"
    );
    close_all(&runtime).await;
    assert_eq!(
        runtime.udp_sessions().association_slots.available_permits(),
        UDP_ASSOCIATIONS_GLOBAL
    );
    dns_task.abort();
}

#[tokio::test]
async fn direct_domain_datagrams_use_direct_dns_policy_and_respect_zero_ttl() {
    let (dns, dns_task, queries) = dns_stub_with_ttl(0).await;
    let mut profile = configured_profile(dns);
    profile.dns.direct_nameservers = profile.dns.nameservers.clone();
    let mut wrong = profile.dns.nameservers[0].clone();
    wrong.port = 9;
    profile.dns.proxy_nameservers = vec![wrong.clone()];
    profile.dns.nameservers = vec![wrong];
    let core = NativeCoreDevice::compile(&profile);
    let runtime = core.pinned_runtime();
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let flow = TunFlow::open(&runtime, "127.0.0.1:55400");
    let destination = target("direct.test", server.local_addr().unwrap().port());
    let mut peers = Vec::new();
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        flow.send(&destination, payload).await;
        let mut buffer = [0; 16];
        let (len, peer) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], payload);
        peers.push(peer);
    }
    assert_eq!(
        peers[0], peers[1],
        "DNS refresh does not replace the UDP mapping"
    );
    assert_eq!(
        queries.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "TTL zero cannot be hidden behind a second permanent per-session cache"
    );
    close_all(&runtime).await;
    dns_task.abort();
}

#[tokio::test]
async fn explicit_and_virtual_proxy_datagrams_use_core_dns_without_remote_resolution() {
    let (dns, dns_task, queries) = dns_stub_with_ttl(0).await;
    let (proxy, mut requests, _closed, proxy_task) = socks_proxy().await;
    let mut profile = configured_profile(dns);
    // Business names must use nameservers. Neither the DIRECT override nor
    // node bootstrap is a valid substitute for the application's DNS policy.
    let mut wrong = profile.dns.nameservers[0].clone();
    wrong.port = 9;
    profile.dns.direct_nameservers = vec![wrong.clone()];
    profile.dns.proxy_nameservers = vec![wrong];
    profile.proxies.push(ProxyNode {
        id: "socks".into(),
        name: "socks".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some(proxy.ip().to_string()),
        port: Some(proxy.port()),
        options: serde_json::json!({"udp": true}),
    });
    profile.rules = profile
        .rules
        .iter()
        .chain([RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "socks",
            no_resolve: false,
        }])
        .collect();
    let core = NativeCoreDevice::compile(&profile);
    let runtime = core.pinned_runtime();
    let user: Option<Arc<str>> = Some(Arc::from("explicit-client"));
    let source: SocketAddr = "127.0.0.1:55410".parse().unwrap();
    let send_face = |destination: ConnectTarget, payload: &'static [u8]| {
        let datagram = UdpDatagram {
            flow_id: Some("explicit-face".into()),
            pump_queue: None,
            inbound: "udp-associate",
            user: user.clone(),
            source,
            target: destination,
            payload: payload.to_vec(),
            process_name: None,
            process_path: None,
        };
        send_udp_flow_datagram(&runtime, datagram)
    };
    send_face(target("a.test", 443), b"first").await.unwrap();
    let first = timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.target, target("127.0.0.1", 443));
    assert_eq!(
        queries.load(Ordering::Relaxed),
        1,
        "connect and first send share one resolution"
    );
    send_face(target("a.test", 444), b"second").await.unwrap();
    let second = timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(second.target, target("127.0.0.1", 444));
    assert_eq!(second.peer, first.peer);
    assert_eq!(
        queries.load(Ordering::Relaxed),
        2,
        "zero TTL is observed by the next datagram"
    );

    send_face(target("bad.test", 443), b"discarded")
        .await
        .unwrap();
    send_face(target("b.test", 445), b"after-dns-error")
        .await
        .unwrap();
    let after_error = timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_error.payload, b"after-dns-error");
    assert_eq!(after_error.target, target("127.0.0.1", 445));
    assert_eq!(
        after_error.peer, first.peer,
        "one DNS failure does not replace the mapping"
    );
    assert_eq!(core.state_audit().udp_transport.packet_errors, 1);
    assert_eq!(core.state_audit().udp_transport.failures, 0);
    first
        .reply(target("127.0.0.1", 8443), b"actual-source")
        .await;
    let replies = drain_udp_face_responses(
        &runtime,
        &user,
        Some("explicit-face"),
        1,
        Duration::from_secs(3),
    )
    .await;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].source_endpoint, target("127.0.0.1", 8443));

    let flow = TunFlow::open(&runtime, "127.0.0.1:55411");
    let fake = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("a.test")
            .unwrap()
            .to_string(),
        443,
    );
    flow.send(&fake, b"captured").await;
    let captured = timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        captured.target, first.target,
        "both ingress modes use the same DNS result"
    );
    captured
        .reply(target("127.0.0.1", 9443), b"fake-source")
        .await;
    let replies = flow.recv_batch(1).await;
    assert_eq!(replies[0].source_endpoint.host, fake.host);
    assert_eq!(replies[0].source_endpoint.port, 9443);
    drop(replies);
    assert!(
        requests.try_recv().is_err(),
        "failed payloads are not replayed"
    );
    close_all(&runtime).await;
    close_udp_flow_sessions(&runtime, "explicit-face").unwrap();
    proxy_task.abort();
    dns_task.abort();
}

/// Asks the DNS stub at `dns` a question a proxy relayed, as the proxy
/// would, and returns the answer.
async fn relay_question(dns: SocketAddr, question: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket.send_to(question, dns).await.unwrap();
    let mut answer = vec![0; 4096];
    let len = timeout(Duration::from_secs(3), socket.recv(&mut answer))
        .await
        .unwrap()
        .unwrap();
    answer.truncate(len);
    answer
}

async fn next_request(requests: &mut mpsc::Receiver<ProxyDatagram>) -> ProxyDatagram {
    timeout(Duration::from_secs(3), requests.recv())
        .await
        .unwrap()
        .unwrap()
}

fn strict_global_profile(dns: SocketAddr, proxy: SocketAddr) -> RuntimeProfile {
    let mut profile = configured_profile(dns);
    profile.proxies.push(ProxyNode {
        id: "socks".into(),
        name: "socks".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some(proxy.ip().to_string()),
        port: Some(proxy.port()),
        options: serde_json::json!({"udp": true}),
    });
    profile.traffic_policy_mode = TrafficPolicyMode::Global;
    profile.global_outbound = Some("socks".into());
    profile
}

/// Strict global mode asks the configured server through the proxy: a fake
/// IP's name resolves past it, then its identity joins the association the
/// client's real targets use, so a STUN server reached by name and a peer
/// reached by address see one mapping (EIM), and no question leaves short of
/// the proxy.
#[tokio::test]
async fn strict_global_names_resolve_through_the_proxy_onto_one_mapping() {
    let (dns, dns_task, queries) = dns_stub_with_ttl(30).await;
    let (proxy, mut requests, _closed, proxy_task) = socks_proxy().await;
    let core = NativeCoreDevice::compile(&strict_global_profile(dns, proxy));
    let runtime = core.pinned_runtime();
    let flow = TunFlow::open(&runtime, "127.0.0.1:55421");
    let fake = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("a.test")
            .unwrap()
            .to_string(),
        3478,
    );
    flow.send(&fake, b"by-name").await;
    let question = next_request(&mut requests).await;
    let server = target(&dns.ip().to_string(), dns.port());
    assert_eq!(
        question.target, server,
        "the question goes through the proxy"
    );
    question
        .reply(server, &relay_question(dns, &question.payload).await)
        .await;
    let by_name = next_request(&mut requests).await;
    assert_eq!(by_name.payload, b"by-name");
    assert_eq!(
        by_name.target,
        target("127.0.0.1", 3478),
        "the proxy gets the address the name resolved to"
    );
    flow.send(&target("192.0.2.10", 3479), b"by-address").await;
    let by_address = next_request(&mut requests).await;
    assert_eq!(
        by_address.peer, by_name.peer,
        "the name and the address share one association (EIM)"
    );
    by_name
        .reply(target("127.0.0.1", 3478), b"from-the-name")
        .await;
    by_address
        .reply(target("192.0.2.10", 3479), b"from-the-address")
        .await;
    let mut replies = HashMap::new();
    while replies.len() < 2 {
        for reply in flow.recv_batch(8).await {
            replies.insert(reply.payload.clone(), reply.source_endpoint.clone());
        }
    }
    assert_eq!(replies[b"from-the-name".as_slice()], fake);
    assert_eq!(
        replies[b"from-the-address".as_slice()],
        target("192.0.2.10", 3479)
    );
    assert_eq!(
        queries.load(Ordering::Relaxed),
        1,
        "the one question came through the proxy"
    );
    close_all(&runtime).await;
    proxy_task.abort();
    dns_task.abort();
}

/// Strict global mode with no server but the local resolver, which it never
/// asks: a captured datagram to a fake IP reaches the proxy by name on an
/// association of its own, and replies from the address the proxy reports
/// come back from the fake IP.
#[tokio::test]
async fn strict_global_names_only_the_local_resolver_answers_go_to_the_proxy() {
    let (dns, dns_task, queries) = dns_stub_with_ttl(30).await;
    let (proxy, mut requests, _closed, proxy_task) = socks_proxy().await;
    let mut profile = strict_global_profile(dns, proxy);
    // The stub stands in for the lists no business name may use.
    profile.dns.direct_nameservers = profile.dns.nameservers.clone();
    profile.dns.proxy_nameservers = profile.dns.nameservers.clone();
    profile.dns.nameservers = vec![DnsUpstream {
        route: Some(DnsRoute::Direct),
        ..DnsUpstream::system()
    }];
    let core = NativeCoreDevice::compile(&profile);
    let runtime = core.pinned_runtime();
    let flow = TunFlow::open(&runtime, "127.0.0.1:55420");
    let fake = target(
        &runtime
            .fake_dns()
            .allocate_ipv4("a.test")
            .unwrap()
            .to_string(),
        443,
    );
    flow.send(&fake, b"captured").await;
    let captured = next_request(&mut requests).await;
    assert_eq!(captured.target, target("a.test", 443));
    flow.send(&target("192.0.2.10", 3479), b"by-address").await;
    let by_address = next_request(&mut requests).await;
    assert_ne!(
        by_address.peer, captured.peer,
        "a name the proxy resolves has an association of its own"
    );
    captured
        .reply(target("203.0.113.7", 443), b"from-the-name")
        .await;
    let replies = flow.recv_batch(1).await;
    assert_eq!(replies[0].source_endpoint, fake);
    drop(replies);
    captured
        .reply(target("198.51.100.4", 3479), b"from-another-peer")
        .await;
    let replies = flow.recv_batch(1).await;
    assert_eq!(replies[0].source_endpoint, target("198.51.100.4", 3479));
    drop(replies);
    assert_eq!(
        queries.load(Ordering::Relaxed),
        0,
        "no business name resolves short of the proxy"
    );
    close_all(&runtime).await;
    proxy_task.abort();
    dns_task.abort();
}

/// A new association to a name meets an IP rule that may resolve it: the
/// datagram waits in its own task while the name resolves, then the rule
/// routes it, a captured fake IP included. With `no-resolve` the name goes on
/// to the next rule untouched.
#[tokio::test]
async fn an_ip_rule_routes_a_new_association_once_its_name_resolves() {
    for no_resolve in [false, true] {
        let (dns, dns_task, queries) = dns_stub_with_ttl(60).await;
        let (proxy, mut requests, _closed, proxy_task) = socks_proxy().await;
        let mut profile = configured_profile(dns);
        profile.proxies.push(ProxyNode {
            id: "socks".into(),
            name: "socks".into(),
            protocol: ProxyProtocol::Socks5,
            server: Some(proxy.ip().to_string()),
            port: Some(proxy.port()),
            options: serde_json::json!({"udp": true}),
        });
        profile.rules = vec![
            RouteRule {
                kind: RuleKind::GeoIp,
                payload: Some("CN"),
                outbound: "DIRECT",
                no_resolve,
            },
            RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: "socks",
                no_resolve: false,
            },
        ]
        .into();
        profile.geodata.geoip = Some(vec![crate::geodata::GeoIpContent {
            code: "CN".into(),
            cidrs: ["127.0.0.0/8"].into_iter().collect(),
            inverse: false,
        }]);
        let core = NativeCoreDevice::compile(&profile);
        let runtime = core.pinned_runtime();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = server.local_addr().unwrap().port();
        let fake = runtime
            .fake_dns()
            .allocate_ipv4("geo.test")
            .unwrap()
            .to_string();
        for (flow, destination) in [
            ("127.0.0.1:55420", target("geo.test", port)),
            ("127.0.0.1:55421", target(&fake, port)),
        ] {
            let flow = TunFlow::open(&runtime, flow);
            flow.send(&destination, b"geo").await;
            if no_resolve {
                let request = timeout(Duration::from_secs(3), requests.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(request.payload, b"geo");
            } else {
                let mut buffer = [0; 8];
                let (len, _) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
                    .await
                    .expect("the DIRECT rule takes the resolved name")
                    .unwrap();
                assert_eq!(&buffer[..len], b"geo");
            }
        }
        let sessions = runtime.udp_sessions().sessions_snapshot();
        assert_eq!(sessions.len(), 2);
        let expected = if no_resolve {
            "MATCH,socks"
        } else {
            "GEOIP,CN,DIRECT"
        };
        assert!(
            sessions
                .iter()
                .all(|session| session.matched_rule.as_deref() == Some(expected)),
            "{sessions:?}"
        );
        if !no_resolve {
            assert!(requests.try_recv().is_err(), "nothing reached the proxy");
        }
        assert!(queries.load(std::sync::atomic::Ordering::Relaxed) > 0);
        close_all(&runtime).await;
        proxy_task.abort();
        dns_task.abort();
    }
}

#[tokio::test]
async fn literal_ipv6_direct_and_proxy_targets_work_with_dns_ipv6_disabled() {
    let (dns, dns_task, queries) = dns_stub_with_ttl(0).await;
    let (proxy, mut requests, _closed, proxy_task) = socks_proxy().await;
    let mut profile = configured_profile(dns);
    profile.proxies.push(ProxyNode {
        id: "socks".into(),
        name: "socks".into(),
        protocol: ProxyProtocol::Socks5,
        server: Some(proxy.ip().to_string()),
        port: Some(proxy.port()),
        options: serde_json::json!({"udp": true}),
    });
    profile.rules = profile
        .rules
        .iter()
        .chain([RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "socks",
            no_resolve: false,
        }])
        .collect();
    let core = NativeCoreDevice::compile(&profile);
    let runtime = core.pinned_runtime();
    assert!(!core.ipv6_enabled());
    let v4 = target("192.0.2.1", 443);
    let v6 = target("2001:db8::1", 8443);
    for targets in [[&v6, &v4], [&v4, &v6]] {
        let flow = TunFlow::open(&runtime, "127.0.0.1:55412");
        let mut peers = Vec::new();
        for destination in targets {
            flow.send(destination, b"numeric").await;
            let request = timeout(Duration::from_secs(3), requests.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                &request.target, destination,
                "the literal target must reach the proxy unchanged"
            );
            peers.push(request.peer);
            request
                .reply(target("2001:db8::2", 9443), b"numeric-reply")
                .await;
            let replies = flow.recv_batch(1).await;
            assert_eq!(replies[0].source_endpoint.host, "2001:db8::2");
            assert_eq!(replies[0].source_endpoint.port, 9443);
        }
        assert_eq!(
            peers[0], peers[1],
            "both destination families share the real association"
        );
        flow.close().await;
    }
    close_all(&runtime).await;

    let direct = NativeCoreDevice::compile(&configured_profile(dns));
    let direct_runtime = direct.pinned_runtime();
    let direct_flow = TunFlow::open(&direct_runtime, "127.0.0.1:55413");
    let echo = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let destination = target("::1", echo.local_addr().unwrap().port());
    direct_flow.send(&destination, b"direct-ipv6").await;
    let mut bytes = [0; 32];
    let (len, peer) = timeout(Duration::from_secs(3), echo.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes[..len], b"direct-ipv6");
    echo.send_to(&bytes[..len], peer).await.unwrap();
    let replies = direct_flow.recv_batch(1).await;
    assert_eq!(replies[0].payload, b"direct-ipv6");
    assert_eq!(replies[0].source_endpoint.host, "::1");
    assert_eq!(replies[0].source_endpoint.port, destination.port);
    assert_eq!(direct.state_audit().udp_session_sockets, 1);
    assert_eq!(
        queries.load(Ordering::Relaxed),
        0,
        "literal targets never query DNS"
    );
    close_all(&direct_runtime).await;
    proxy_task.abort();
    dns_task.abort();
}

#[tokio::test]
async fn direct_real_owner_supports_both_families_and_ipv6_only_domain_in_either_order() {
    use crate::egress::{
        EgressAddressFamily, EgressBinding, EgressSocketContext, EgressSocketDescriptor,
        EgressSocketGuard, NativeCoreEgressConfig,
    };
    #[derive(Debug, Default)]
    struct Guard(Mutex<Vec<EgressSocketContext>>);
    impl EgressSocketGuard for Guard {
        fn protect_socket(
            &self,
            _: EgressSocketDescriptor,
            context: EgressSocketContext,
        ) -> Result<EgressBinding, String> {
            self.0.lock().unwrap().push(context);
            Ok(EgressBinding::unbound())
        }
    }
    let (dns, dns_task) = dns_stub().await;
    let profile = configured_profile(dns);
    let guard = Arc::new(Guard::default());
    let core = NativeCoreDevice::from_start_inputs(crate::CoreStartInputs {
        profile,
        egress: NativeCoreEgressConfig {
            ipv6_enabled: true,
            ..Default::default()
        },
        egress_socket_guard: Some(guard.clone()),
        capture: Default::default(),
        flow_scanner: None,
        fake_ip_mappings: None,
    });
    let runtime = core.pinned_runtime();
    let server4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let server6 = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let target4 = target("127.0.0.1", server4.local_addr().unwrap().port());
    let target6 = target("v6.test", server6.local_addr().unwrap().port());
    for ipv6_first in [false, true] {
        let flow = TunFlow::open(
            &runtime,
            &SocketAddr::from((Ipv4Addr::LOCALHOST, 55401)).to_string(),
        );
        let ordered = if ipv6_first {
            [
                (&target6, &server6, b"v6".as_slice()),
                (&target4, &server4, b"v4".as_slice()),
            ]
        } else {
            [
                (&target4, &server4, b"v4".as_slice()),
                (&target6, &server6, b"v6".as_slice()),
            ]
        };
        let mut peers = Vec::new();
        for (destination, server, payload) in ordered {
            flow.send(destination, payload).await;
            let mut buffer = [0; 16];
            let (len, peer) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..len], payload);
            peers.push((server, peer, payload));
        }
        assert!(flow.is_open());
        assert_eq!(core.state_audit().udp_sessions, 1);
        assert_eq!(
            core.state_audit().udp_session_sockets,
            1,
            "families share the same Real association"
        );
        for (server, peer, payload) in peers.iter().rev() {
            server.send_to(payload, peer).await.unwrap();
        }
        let mut replies = HashMap::new();
        while replies.len() < 2 {
            let batch = flow.recv_batch(64).await;
            for reply in batch {
                replies.insert(
                    reply.payload.clone(),
                    target(&reply.source_endpoint.host, reply.source_endpoint.port),
                );
            }
        }
        assert_eq!(replies[b"v4".as_slice()], target4);
        assert_eq!(
            replies[b"v6".as_slice()],
            target("::1", server6.local_addr().unwrap().port())
        );
        flow.close().await;
    }
    let contexts = guard.0.lock().unwrap();
    let shared: Vec<_> = contexts
        .iter()
        .filter(|context| context.remote.is_none())
        .collect();
    assert_eq!(
        shared
            .iter()
            .filter(|context| context.family == EgressAddressFamily::Ipv4)
            .count(),
        2
    );
    assert_eq!(
        shared
            .iter()
            .filter(|context| context.family == EgressAddressFamily::Ipv6)
            .count(),
        2
    );
    drop(contexts);
    close_all(&runtime).await;
    dns_task.abort();
}

#[tokio::test]
async fn oversized_native_send_preserves_mapping_and_large_reply_arrives_complete() {
    let core = NativeCoreDevice::compile(&RuntimeProfile::new("udp-packet-size"));
    let runtime = core.pinned_runtime();
    let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let destination = target("127.0.0.1", server.local_addr().unwrap().port());
    let flow = TunFlow::open(&runtime, "127.0.0.1:55500");
    flow.send(&destination, b"before-size-error").await;
    let mut buffer = [0; 64];
    let (len, first_peer) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], b"before-size-error");
    // This fits the core's generic UDP payload vocabulary but exceeds IPv4's
    // physical UDP maximum. The OS returns its native size error; no errno or
    // error-text matching is required to retain the mapping.
    flow.send(&destination, &vec![0xa7; 65535]).await;
    flow.send(&destination, b"after-size-error").await;
    let (len, second_peer) = timeout(Duration::from_secs(3), server.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], b"after-size-error");
    assert_eq!(first_peer, second_peer);
    assert!(flow.is_open());
    let diagnostics = core.state_audit().udp_transport;
    assert_eq!(diagnostics.failures, 0);
    assert_eq!(diagnostics.packet_errors, 1);
    assert_eq!(
        diagnostics.recent_packet_errors[0].stage,
        UdpTransportStage::Send
    );
    assert!(matches!(
        diagnostics.recent_packet_errors[0].cause,
        UdpTransportFailureCause::Io {
            source: UdpTransportErrorSource::NativeSocket,
            ..
        }
    ));

    let payload: Vec<u8> = (0..48 * 1024).map(|index| (index % 251) as u8).collect();
    flow.send(&destination, &payload).await;
    let mut large_buffer = vec![0; crate::outbound::UDP_DATAGRAM_CAPACITY];
    let (len, large_peer) = timeout(Duration::from_secs(3), server.recv_from(&mut large_buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &large_buffer[..len],
        payload.as_slice(),
        "Core sockets accept legal packets beyond the host's default send buffer"
    );
    assert_eq!(large_peer, first_peer);
    socket2::SockRef::from(&server)
        .set_send_buffer_size(crate::outbound::UDP_DATAGRAM_CAPACITY)
        .unwrap();
    server.send_to(&payload, second_peer).await.unwrap();
    let received = flow.recv_batch(64).await;
    assert_eq!(received.len(), 1);
    assert_eq!(
        received[0].payload, payload,
        "UDP payloads must never be silently truncated"
    );
    drop(received);
    close_all(&runtime).await;
}
