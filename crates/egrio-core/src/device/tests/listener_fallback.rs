//! A requested listener port that is taken: the start fails and says why, or,
//! when the host lets another port stand in, the listener serves on a free
//! one nearby and its status reports the switch until it stops.
use super::*;
use crate::inbound::CoreSessionManager;
use crate::{NativeCoreState, PortUnavailable};

#[tokio::test]
async fn a_taken_port_fails_the_start_when_no_other_port_may_stand_in() {
    let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let taken = holder.local_addr().unwrap();
    let core = NativeCoreDevice::compile(&direct_profile());
    let error = CoreSessionManager::default()
        .start_on_device(core, Some(taken), None, false)
        .await
        .unwrap_err();
    assert!(
        error.starts_with(&format!(
            "cannot listen on {taken}: another program already uses this port; choose another port"
        )),
        "{error}"
    );
}

#[tokio::test]
async fn a_taken_port_gives_way_to_a_free_one_and_the_status_says_why() {
    let holder = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let taken = holder.local_addr().unwrap();
    let core = NativeCoreDevice::compile(&direct_profile());
    let manager = CoreSessionManager::default();
    let status = manager
        .start_on_device(core, Some(taken), None, true)
        .await
        .unwrap();

    let bound: SocketAddr = status.listen_addr.as_deref().unwrap().parse().unwrap();
    assert_eq!(bound.ip(), taken.ip());
    assert_ne!(bound.port(), taken.port());
    let fallback = status.listener_fallback.expect("the switch is reported");
    assert_eq!(fallback.requested, taken.to_string());
    assert_eq!(fallback.cause, PortUnavailable::InUse);
    assert!(!fallback.detail.is_empty());
    TcpStream::connect(bound)
        .await
        .expect("the stand-in port serves");

    manager.stop();
    timeout(Duration::from_secs(5), async {
        while manager.status().state != NativeCoreState::Stopped {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the listener stops");
    assert!(manager.status().listener_fallback.is_none());
}
