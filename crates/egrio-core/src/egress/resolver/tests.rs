use super::*;
use crate::egress::NativeCoreEgressConfig;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

struct Stub {
    address: SocketAddr,
    queries: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn stub(
    response: impl Fn(&[u8], usize) -> Option<(Duration, Vec<u8>)> + Send + 'static,
) -> Stub {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    let queries = Arc::new(AtomicUsize::new(0));
    let count = queries.clone();
    let task = tokio::spawn(async move {
        let mut query = [0; 512];
        loop {
            let (length, peer) = socket.recv_from(&mut query).await.unwrap();
            let index = count.fetch_add(1, Ordering::SeqCst);
            if let Some((delay, reply)) = response(&query[..length], index) {
                let socket = socket.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    socket.send_to(&reply, peer).await.unwrap();
                });
            }
        }
    });
    Stub {
        address,
        queries,
        task,
    }
}

fn response(query: &[u8], address: IpAddr, ttl: u32) -> Vec<u8> {
    let mut response = query.to_vec();
    response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    response[6..8].copy_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c]);
    let (kind, bytes) = match address {
        IpAddr::V4(ip) => (DNS_TYPE_A, ip.octets().to_vec()),
        IpAddr::V6(ip) => (DNS_TYPE_AAAA, ip.octets().to_vec()),
    };
    response.extend_from_slice(&kind.to_be_bytes());
    response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    response.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    response.extend_from_slice(&bytes);
    response
}

fn runtime(servers: Vec<SocketAddr>, ipv6: bool) -> EgressRuntime {
    EgressRuntime::new(NativeCoreEgressConfig {
        dns_servers: servers,
        ipv6_enabled: ipv6,
        ..Default::default()
    })
}

fn negative_response(query: &[u8], rcode: u16) -> Vec<u8> {
    let mut reply = query.to_vec();
    reply[2..4].copy_from_slice(&(0x8180 | rcode).to_be_bytes());
    reply
}

#[tokio::test]
async fn nxdomain_does_not_failover_or_become_a_tcp_destination() {
    let negative = stub(|query, _| Some((Duration::ZERO, negative_response(query, 3)))).await;
    let alternate = stub(|query, _| {
        Some((
            Duration::ZERO,
            response(query, "192.0.2.1".parse().unwrap(), 60),
        ))
    })
    .await;
    let egress = runtime(vec![negative.address, alternate.address], false);
    let answer = egress
        .resolver
        .resolve(&egress, "absent.test", DNS_TYPE_A)
        .await
        .unwrap();
    assert_eq!(u16::from(answer.response_code()), 3);
    assert!(answer.answers().is_empty());
    assert_eq!(alternate.queries.load(Ordering::SeqCst), 0);
    assert!(egress
        .connect_tcp_host("absent.test", 443, "test")
        .await
        .is_err());
    assert_eq!(alternate.queries.load(Ordering::SeqCst), 0);
    assert_eq!(
        negative.queries.load(Ordering::SeqCst),
        2,
        "no negative cache was added"
    );
}

#[tokio::test]
async fn servfail_can_use_another_configured_resolver() {
    let failed = stub(|query, _| Some((Duration::ZERO, negative_response(query, 2)))).await;
    let alternate = stub(|query, _| {
        Some((
            Duration::ZERO,
            response(query, "192.0.2.1".parse().unwrap(), 60),
        ))
    })
    .await;
    let egress = runtime(vec![failed.address, alternate.address], false);
    let answer = egress
        .resolver
        .resolve(&egress, "available.test", DNS_TYPE_A)
        .await
        .unwrap();
    assert_eq!(answer.response_code(), ResponseCode::NoError);
    assert_eq!(
        wire::addresses(&answer).unwrap(),
        vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
    assert_eq!(failed.queries.load(Ordering::SeqCst), 1);
    assert_eq!(alternate.queries.load(Ordering::SeqCst), 1);
}

#[test]
fn formerr_without_an_echoed_question_is_a_dns_response_not_a_transport_failure() {
    let id = 0x1234u16;
    let mut response = vec![0; 12];
    response[..2].copy_from_slice(&id.to_be_bytes());
    response[2..4].copy_from_slice(&0x8001u16.to_be_bytes());
    let WireAnswer::Complete(answer) =
        parse_response(&response, id, "invalid.test", DNS_TYPE_A).unwrap()
    else {
        panic!("unexpected truncation");
    };
    assert_eq!(u16::from(answer.response_code), 1);
    assert!(answer.addresses.is_empty());
}

#[tokio::test]
async fn silent_first_server_does_not_consume_fallback_budget() {
    let silent = stub(|_, _| None).await;
    let good = stub(|query, _| {
        Some((
            Duration::ZERO,
            response(query, "192.0.2.1".parse().unwrap(), 60),
        ))
    })
    .await;
    let egress = runtime(vec![silent.address, good.address], false);
    let addresses = timeout(
        Duration::from_secs(1),
        egress.lookup_host_record("fallback.test", 80, false),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(addresses, vec!["192.0.2.1:80".parse().unwrap()]);
    assert_eq!(silent.queries.load(Ordering::SeqCst), 1);
    assert_eq!(good.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn address_record_queries_do_not_wait_for_the_other_family() {
    let dns = stub(|query, _| {
        (word(query, query.len() - 4).unwrap() == DNS_TYPE_A).then(|| {
            (
                Duration::ZERO,
                response(query, "192.0.2.1".parse().unwrap(), 60),
            )
        })
    })
    .await;
    let egress = runtime(vec![dns.address], true);
    let addresses = timeout(
        Duration::from_millis(300),
        egress.lookup_host_record("family.test", 80, false),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(addresses.len(), 1);
    assert_eq!(dns.queries.load(Ordering::SeqCst), 1);
    let available = timeout(
        Duration::from_secs(3),
        egress.lookup_host("family.test", 80),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(available, addresses);
}

#[tokio::test]
async fn complete_lookup_keeps_ipv4_first_when_aaaa_arrives_before_a() {
    let dns = stub(|query, _| {
        let (delay, address) = if word(query, query.len() - 4).unwrap() == DNS_TYPE_A {
            (Duration::from_millis(100), "192.0.2.1")
        } else {
            (Duration::ZERO, "2001:db8::1")
        };
        Some((delay, response(query, address.parse().unwrap(), 60)))
    })
    .await;
    let egress = runtime(vec![dns.address], true);
    let addresses = timeout(
        Duration::from_secs(1),
        egress.lookup_host("arrival.test", 443),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        addresses,
        vec![
            "192.0.2.1:443".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap()
        ]
    );
    // UDP and Hysteria2 use this selector; a fast AAAA must not silently
    // replace their existing IPv4 preference with DNS response-order policy.
    assert_eq!(
        egress
            .udp_remote_addr_for_host("arrival.test", 443)
            .await
            .unwrap(),
        addresses[0]
    );
}

#[tokio::test]
async fn complete_lookup_keeps_ipv6_when_ipv4_resolution_times_out() {
    let dns = stub(|query, _| {
        (word(query, query.len() - 4).unwrap() == DNS_TYPE_AAAA).then(|| {
            (
                Duration::ZERO,
                response(query, "2001:db8::1".parse().unwrap(), 60),
            )
        })
    })
    .await;
    let egress = runtime(vec![dns.address], true);
    let addresses = timeout(
        Duration::from_secs(3),
        egress.lookup_host("v6-only.test", 443),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(addresses, vec!["[2001:db8::1]:443".parse().unwrap()]);
}

#[tokio::test]
async fn concurrent_cold_queries_share_one_normalized_lookup() {
    let dns = stub(|query, _| {
        Some((
            Duration::from_millis(50),
            response(query, "192.0.2.1".parse().unwrap(), 60),
        ))
    })
    .await;
    let egress = Arc::new(runtime(vec![dns.address], false));
    let mut callers = tokio::task::JoinSet::new();
    for index in 0..32 {
        let egress = egress.clone();
        callers.spawn(async move {
            egress
                .lookup_host(
                    if index % 2 == 0 {
                        "NODE.Test."
                    } else {
                        "node.test"
                    },
                    80,
                )
                .await
                .unwrap()
        });
    }
    while let Some(result) = callers.join_next().await {
        assert_eq!(result.unwrap().len(), 1);
    }
    assert_eq!(dns.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_singleflight_owner_allows_waiter_to_retry() {
    let dns = stub(|query, index| {
        (index > 0).then(|| {
            (
                Duration::ZERO,
                response(query, "192.0.2.1".parse().unwrap(), 60),
            )
        })
    })
    .await;
    let egress = Arc::new(runtime(vec![dns.address], false));
    let owner_egress = egress.clone();
    let owner = tokio::spawn(async move { owner_egress.lookup_host("cancel.test", 80).await });
    timeout(Duration::from_secs(1), async {
        while dns.queries.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let waiter_egress = egress.clone();
    let waiter = tokio::spawn(async move { waiter_egress.lookup_host("cancel.test", 80).await });
    tokio::task::yield_now().await;
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
    assert_eq!(
        timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(dns.queries.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn zero_and_high_bit_ttls_are_never_cached() {
    for ttl in [0, 0x8000_0001, u32::MAX] {
        let dns = stub(move |query, _| {
            Some((
                Duration::ZERO,
                response(query, "192.0.2.1".parse().unwrap(), ttl),
            ))
        })
        .await;
        let egress = runtime(vec![dns.address], false);
        for _ in 0..2 {
            egress.lookup_host("ttl.test", 80).await.unwrap();
        }
        assert_eq!(dns.queries.load(Ordering::SeqCst), 2, "TTL {ttl}");
    }
}

#[tokio::test]
async fn cached_record_expires_at_its_wire_ttl() {
    let dns = stub(|query, _| {
        Some((
            Duration::ZERO,
            response(query, "192.0.2.1".parse().unwrap(), 1),
        ))
    })
    .await;
    let egress = runtime(vec![dns.address], false);
    egress.lookup_host("expiry.test", 80).await.unwrap();
    egress.lookup_host("expiry.test", 80).await.unwrap();
    assert_eq!(dns.queries.load(Ordering::SeqCst), 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::time::resume();
    egress.lookup_host("expiry.test", 80).await.unwrap();
    assert_eq!(dns.queries.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn truncated_udp_retries_tcp_even_for_a_private_configured_resolver() {
    let dns = stub(|query, _| {
        let mut reply = query.to_vec();
        reply[2..4].copy_from_slice(&0x8380u16.to_be_bytes());
        Some((Duration::ZERO, reply))
    })
    .await;
    let listener = TcpListener::bind(dns.address).await.unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap() as usize;
        let mut query = vec![0; length];
        stream.read_exact(&mut query).await.unwrap();
        let reply = response(&query, "192.0.2.1".parse().unwrap(), 60);
        stream.write_u16(reply.len() as u16).await.unwrap();
        stream.write_all(&reply).await.unwrap();
    });
    let mut egress = runtime(vec![dns.address], false);
    egress.config.refuse_private_destinations = true;
    let addresses = timeout(
        Duration::from_secs(1),
        egress.lookup_host("truncated.test", 80),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(addresses, vec!["192.0.2.1:80".parse().unwrap()]);
    server.await.unwrap();
}

#[tokio::test]
async fn mismatched_datagram_id_does_not_discard_a_valid_later_response() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let egress = runtime(vec![socket.local_addr().unwrap()], false);
    let server = tokio::spawn(async move {
        let mut query = [0; 512];
        let (length, peer) = socket.recv_from(&mut query).await.unwrap();
        let good = response(&query[..length], "192.0.2.1".parse().unwrap(), 60);
        let mut stale = good.clone();
        stale[0] ^= 1;
        socket.send_to(&stale, peer).await.unwrap();
        socket.send_to(&good, peer).await.unwrap();
    });
    assert_eq!(egress.lookup_host("id.test", 80).await.unwrap().len(), 1);
    server.await.unwrap();
}

#[test]
fn cname_ttl_limits_the_final_address_and_unrelated_records_are_ignored() {
    let (id, query) = build_query("alias.test", DNS_TYPE_A).unwrap();
    let mut reply = response(&query, "192.0.2.99".parse().unwrap(), 60);
    // This address record is for an unrelated owner and must not become an
    // egress destination just because its type matches the query.
    let owner = reply.len() - 16;
    reply[owner..owner + 2].copy_from_slice(&[0xc0, 0x12]);
    assert!(
        parse_response(&reply, id, "alias.test", DNS_TYPE_A).is_err()
            || matches!(parse_response(&reply, id, "alias.test", DNS_TYPE_A), Ok(WireAnswer::Complete(TestAnswer { addresses, .. })) if addresses.is_empty())
    );

    let mut reply = query.clone();
    reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    reply[6..8].copy_from_slice(&2u16.to_be_bytes());
    reply.extend_from_slice(&[0xc0, 0x0c]);
    reply.extend_from_slice(&5u16.to_be_bytes());
    reply.extend_from_slice(&1u16.to_be_bytes());
    reply.extend_from_slice(&2u32.to_be_bytes());
    let alias = b"\x04real\x04test\x00";
    reply.extend_from_slice(&(alias.len() as u16).to_be_bytes());
    let alias_offset = reply.len() as u16;
    reply.extend_from_slice(alias);
    reply.extend_from_slice(&(0xc000 | alias_offset).to_be_bytes());
    reply.extend_from_slice(&1u16.to_be_bytes());
    reply.extend_from_slice(&1u16.to_be_bytes());
    reply.extend_from_slice(&60u32.to_be_bytes());
    reply.extend_from_slice(&4u16.to_be_bytes());
    reply.extend_from_slice(&[192, 0, 2, 1]);
    let WireAnswer::Complete(answer) =
        parse_response(&reply, id, "alias.test", DNS_TYPE_A).unwrap()
    else {
        panic!("unexpected TC");
    };
    assert_eq!(answer.ttl, Duration::from_secs(2));
    assert_eq!(
        answer.addresses,
        vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
}
