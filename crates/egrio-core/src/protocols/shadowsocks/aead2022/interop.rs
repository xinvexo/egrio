//! Explicit cross-language gate; no Go toolchain dependency in normal tests.

use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

use crate::{CoreInbound, CoreSessionManager, CoreSessionStartConfig, NativeCoreEgressConfig};

struct Peer(Child);

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "build scripts/validation/ss2022-peer and set EGRIO_SS2022_PEER"]
async fn independent_go_peer_interop() {
    let executable = std::env::var("EGRIO_SS2022_PEER").expect("EGRIO_SS2022_PEER");
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let echo = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(echo).await.unwrap();
    let tcp_task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = tcp.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 4096];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let udp_task = tokio::spawn(async move {
        let mut buffer = [0; 65536];
        while let Ok((read, source)) = udp.recv_from(&mut buffer).await {
            if udp.send_to(&buffer[..read], source).await.is_err() {
                break;
            }
        }
    });
    for method in super::tests::METHODS {
        let config = super::tests::config(method);
        let key = config.server.password().to_string();
        let mut peer = Peer(
            Command::new(&executable)
                .args(["serve", method, &key])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut address = String::new();
        BufReader::new(peer.0.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let address: SocketAddr = address.trim().parse().unwrap();
        let payload = b"egrio-to-independent-go-peer";
        let tcp = timeout(
            Duration::from_secs(10),
            crate::self_test::run_shadowsocks_connect_client(address, method, &key, echo, payload),
        )
        .await
        .unwrap()
        .unwrap();
        let udp = timeout(
            Duration::from_secs(10),
            crate::self_test::run_shadowsocks_udp_client(address, method, &key, echo, payload),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(tcp, payload);
        assert_eq!(udp, payload);
        drop(peer);

        let manager = CoreSessionManager::default();
        manager
            .start_with_config(CoreSessionStartConfig {
                profile: super::tests::profile(),
                egress: NativeCoreEgressConfig::default(),
                listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                dns_listen_addr: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
                inbound: CoreInbound::Shadowsocks {
                    cipher: method.into(),
                    users: vec![("alice".into(), key.clone())],
                },
                hysteria2: None,
                socket_guard: None,
            })
            .await
            .unwrap();
        let server = manager.status().listen_addr.unwrap();
        let mut child = Peer(
            Command::new(&executable)
                .args(["client", method, &key, &server, &echo.to_string()])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        timeout(Duration::from_secs(10), async {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success(), "independent client failed: {method}");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        manager.stop();
        eprintln!("{method}: Egrio -> Go TCP/UDP and Go -> Egrio TCP/UDP OK");
    }
    tcp_task.abort();
    udp_task.abort();
}
