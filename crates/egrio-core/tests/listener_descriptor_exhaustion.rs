//! A listener whose process runs out of descriptors goes on listening.
//!
//! The test takes every descriptor the process may hold, so it is alone in
//! its binary: a test running beside it could open nothing.
#![cfg(unix)]

use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use egrio_core::{CoreSessionManager, NativeCoreState, RouteRule, RuleKind, RuntimeProfile};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// Few enough descriptors that taking them all is quick wherever the test
/// runs, whatever limit it inherited.
const DESCRIPTORS: libc::rlim_t = 256;

fn limit_descriptors() {
    // SAFETY: getrlimit and setrlimit read and write the struct passed to
    // them and nothing else.
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = DESCRIPTORS.min(limit.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
}

fn direct_profile() -> RuntimeProfile {
    let mut profile = RuntimeProfile::new("descriptor-exhaustion");
    profile.rules = vec![RouteRule {
        kind: RuleKind::Match,
        payload: None,
        outbound: "DIRECT",
        no_resolve: false,
    }]
    .into();
    profile
}

/// `accept` fails with `EMFILE` while the process has no descriptor for the
/// connection it would return. That says nothing about the listener, and it
/// passes as soon as anything in the process closes; the connections that
/// come after that are served. The one that met the failure is the kernel's
/// to keep or drop: Linux leaves it in the queue, XNU closes it.
#[tokio::test]
async fn a_listener_out_of_descriptors_serves_again_once_one_is_free() {
    limit_descriptors();
    let manager = CoreSessionManager::default();
    let status = manager.start(direct_profile()).await.unwrap();
    let proxy: SocketAddr = status.listen_addr.unwrap().parse().unwrap();

    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            tokio::spawn(async move {
                let mut bytes = [0_u8; 4];
                if stream.read_exact(&mut bytes).await.is_ok() {
                    let _ = stream.write_all(&bytes).await;
                }
            });
        }
    });

    // The client's socket exists before the descriptors are gone; connecting
    // it needs no further one, and the kernel completes the connection into
    // the listener's queue whether or not anyone accepts it.
    let starved_client = TcpSocket::new_v4().unwrap();
    let mut hoard = Vec::new();
    while let Ok(file) = File::open("/dev/null") {
        hoard.push(file);
    }
    let starved_client = starved_client.connect(proxy).await.unwrap();

    // Long enough for the listener to have tried, failed and tried again.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let starved = manager.status();
    assert_eq!(
        starved.state,
        NativeCoreState::Running,
        "the listener outlives a failed accept: {starved:?}"
    );
    assert!(
        starved
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("accept failed")),
        "the status says why the connection waits: {starved:?}"
    );

    drop(hoard);
    drop(starved_client);
    let served = async {
        let mut client = TcpStream::connect(proxy).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let SocketAddr::V4(target) = upstream_addr else {
            unreachable!("the upstream is bound to an IPv4 address");
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&target.ip().octets());
        request.extend_from_slice(&target.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "the CONNECT is granted");
        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
    };
    tokio::time::timeout(Duration::from_secs(10), served)
        .await
        .expect("a connection made once descriptors are free is served");
    assert_eq!(manager.status().state, NativeCoreState::Running);
    manager.stop();
}
