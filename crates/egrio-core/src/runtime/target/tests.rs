use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{rdata::A, rdata::AAAA, RData, Record, RecordType};
use tokio::io::AsyncReadExt;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::dns::wire;
use crate::egress::NativeCoreEgressConfig;
use crate::outbound::OutboundFuture;
use crate::tcp_flow::TcpFlowFailure;

struct DnsFixture {
    egress: EgressRuntime,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl DnsFixture {
    async fn new(answer_ipv6: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let egress = EgressRuntime::new(NativeCoreEgressConfig {
            dns_servers: vec![socket.local_addr().unwrap()],
            ipv6_enabled: true,
            ..Default::default()
        });
        let socket = Arc::new(socket);
        let task = tokio::spawn(async move {
            let mut bytes = [0; 2048];
            loop {
                let (len, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let request = wire::decode(&bytes[..len]).unwrap();
                // Each query answers on its own, so a slow AAAA does not
                // hold back the A answer.
                let socket = socket.clone();
                tokio::spawn(async move {
                    let query = request.query().unwrap();
                    let mut response = wire::response(&request, ResponseCode::NoError);
                    match query.query_type() {
                        RecordType::A => {
                            for ip in ["192.0.2.1", "192.0.2.2"] {
                                response.add_answer(Record::from_rdata(
                                    query.name().clone(),
                                    60,
                                    RData::A(A(ip.parse().unwrap())),
                                ));
                            }
                        }
                        RecordType::AAAA if answer_ipv6 => {
                            // Past RFC 8305's resolution delay: IPv4 goes first.
                            tokio::time::sleep(Duration::from_millis(150)).await;
                            response.add_answer(Record::from_rdata(
                                query.name().clone(),
                                60,
                                RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
                            ));
                        }
                        // A deliberately silent family must not stall submission
                        // of an already available address for an unconfirmed hop.
                        RecordType::AAAA => return,
                        _ => panic!("unexpected query type"),
                    }
                    socket
                        .send_to(&wire::encode(&response).unwrap(), peer)
                        .await
                        .unwrap();
                });
            }
        });
        Self { egress, task }
    }
}

struct Live(Arc<AtomicUsize>);
impl Drop for Live {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Debug)]
struct Connector {
    direct: bool,
    /// Every attempt fails at once at this stage.
    fails_at: Option<OutboundStage>,
    calls: Mutex<Vec<(String, Vec<u8>)>>,
    live: Arc<AtomicUsize>,
    received: mpsc::UnboundedSender<Vec<u8>>,
}
impl OutboundConnector for Connector {
    fn is_direct(&self) -> bool {
        self.direct
    }

    fn connect_stream<'a>(
        &'a self,
        _egress: &'a EgressRuntime,
        target: &'a ConnectTarget,
        early_data: &'a [u8],
    ) -> OutboundFuture<'a, BoxedOutboundStream> {
        Box::pin(async move {
            assert!(
                !self.direct || target.ip().is_some(),
                "DIRECT dials a numeric target"
            );
            self.calls
                .lock()
                .unwrap()
                .push((target.host.clone(), early_data.to_vec()));
            self.live.fetch_add(1, Ordering::SeqCst);
            let _live = Live(self.live.clone());
            if let Some(stage) = self.fails_at {
                return Err(OutboundError::new(stage, "scripted"));
            }
            if self.direct && target.host != "2001:db8::1" {
                return std::future::pending().await;
            }
            let (stream, mut peer) = tokio::io::duplex(1024);
            let received = self.received.clone();
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                peer.read_to_end(&mut bytes).await.unwrap();
                received.send(bytes).unwrap();
            });
            Ok(Box::new(stream) as BoxedOutboundStream)
        })
    }
}

fn connector(direct: bool) -> (Connector, mpsc::UnboundedReceiver<Vec<u8>>) {
    let (received, incoming) = mpsc::unbounded_channel();
    (
        Connector {
            direct,
            fails_at: None,
            calls: Mutex::default(),
            live: Arc::default(),
            received,
        },
        incoming,
    )
}

fn target() -> ConnectTarget {
    ConnectTarget {
        host: "destination.test".into(),
        port: 443,
    }
}

#[tokio::test]
async fn a_proxy_is_handed_the_name_and_the_core_resolves_nothing() {
    // No DNS server: a lookup would fail the dial.
    let egress = EgressRuntime::new(NativeCoreEgressConfig::default());
    let (connector, mut received) = connector(false);
    let evidence = DialEvidence::default();
    let (stream, _) = connect(
        &egress,
        &connector,
        &target(),
        b"client prefix",
        Instant::now() + Duration::from_secs(2),
        &evidence,
    )
    .await
    .unwrap();
    drop(stream);
    assert_eq!(received.recv().await.unwrap(), b"");
    assert_eq!(
        *connector.calls.lock().unwrap(),
        vec![("destination.test".into(), b"client prefix".to_vec())]
    );
    assert!(evidence.attempted());
}

#[tokio::test]
async fn direct_targets_race_without_replaying_the_client_prefix() {
    let dns = DnsFixture::new(true).await;
    let (connector, mut received) = connector(true);
    let evidence = DialEvidence::default();
    let (stream, _) = tokio::time::timeout(
        Duration::from_secs(2),
        connect(
            &dns.egress,
            &connector,
            &target(),
            b"one client prefix",
            Instant::now() + Duration::from_secs(2),
            &evidence,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    drop(stream);
    assert_eq!(received.recv().await.unwrap(), b"one client prefix");
    let calls = connector.calls.lock().unwrap();
    assert!(
        calls.len() >= 2,
        "a silent IPv4 candidate must be abandoned"
    );
    assert!(calls.iter().all(|(_, early)| early.is_empty()));
    assert_eq!(calls.last().unwrap().0, "2001:db8::1");
    assert_eq!(connector.live.load(Ordering::SeqCst), 0);
    assert!(evidence.attempted());
}

#[tokio::test]
async fn direct_target_failures_try_every_address_and_blame_the_target() {
    let dns = DnsFixture::new(true).await;
    let (mut connector, _) = connector(true);
    connector.fails_at = Some(OutboundStage::Target);
    let error = connect(
        &dns.egress,
        &connector,
        &target(),
        b"",
        Instant::now() + Duration::from_secs(2),
        &DialEvidence::default(),
    )
    .await
    .err()
    .expect("every attempt fails");
    assert!(
        matches!(
            error,
            TcpFlowFailure::Outbound {
                stage: OutboundStage::Target,
                ..
            }
        ),
        "{error}"
    );
    let calls = connector.calls.lock().unwrap();
    assert_eq!(calls.len(), 3, "both families tried: {calls:?}");
}
