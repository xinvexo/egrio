//! The Shadowsocks UDP-associate server face. Unlike Trojan and
//! Hysteria2 — one connection multiplexing one authenticated user's flows behind
//! an `AcceptedDatagramFace` — Shadowsocks UDP is a single socket carrying many
//! users' independently-keyed packets (`salt || AEAD(socks_address || payload)`).
//! So it is a direct-drive server in the packet loop's shape, not
//! an `InboundAcceptor`: each packet is trial-decrypted against the user table
//! (auth is the AEAD tag itself), relayed no-wait through the shared UDP session
//! table, and its responses are drained per user and sealed back to the client.
//!
//! Not server-gated: like the Shadowsocks TCP acceptor it needs no TLS, so a
//! deployment composes it in any build via `CoreInbound::Shadowsocks`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::protocols::shadowsocks::acceptor::ShadowsocksUserTable;
use crate::protocols::shadowsocks::codec::seal_udp_packet;
use crate::udp::{drain_udp_face_responses, send_udp_flow_datagram, UdpDatagram};
use crate::{NativeCoreDevice, NativeCoreDeviceState};

/// Room for a jumbo datagram plus the salt/tag/address envelope (mirrors the
/// connector's receive buffer).
const SHADOWSOCKS_UDP_BUFFER: usize = 64 * 1024;
/// How many queued responses one per-user drain pass delivers, and how long it
/// parks for a response before looping. The park wakes the instant a response
/// lands, so the wait only bounds the idle case.
const UDP_DRAIN_MAX_DATAGRAMS: usize = 256;
const UDP_DRAIN_MAX_WAIT: Duration = Duration::from_secs(1);

/// Aborts the wrapped task on drop, so a per-user drain never outlives the serve
/// loop — including when the serve future is cancelled at shutdown.
/// Serves the Shadowsocks UDP inbound on `socket` until the socket errors (the
/// listener dropped it at shutdown). Spawns one response-drain task per user,
/// then runs the receive loop: trial-decrypt, authenticate, relay no-wait.
pub(crate) async fn serve_shadowsocks_udp(
    socket: Arc<UdpSocket>,
    device: NativeCoreDevice,
    table: Arc<ShadowsocksUserTable>,
    auth_failures: Arc<AtomicU64>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    if table.method().is_aead_2022() {
        super::aead2022::serve(socket, device, table, auth_failures, shutdown_rx).await;
        return;
    }
    let method = table.method();

    // One drain task per user: it owns that user's key, drains only that user's
    // flows, and seals each response back to the client address the flow's
    // source recorded. The guards abort every drain when this serve loop ends.
    //
    // Scoped by flow prefix as well as user: a listener can run this inbound
    // alongside Hysteria2/Trojan, whose user tables are independent, so the
    // same user name can exist in both. On user alone this drain would win
    // another inbound's response and re-seal it with the Shadowsocks key onto
    // the Shadowsocks socket — the datagram would reach the wrong client and
    // the owning face would never see it.
    let mut drains = JoinSet::new();
    for (user, key) in table.user_keys() {
        let device = device.clone();
        let socket = Arc::clone(&socket);
        drains.spawn(async move {
            let flow_prefix = shadowsocks_udp_flow_prefix(&user);
            let user = Some(user);
            loop {
                if matches!(
                    device.status().state,
                    NativeCoreDeviceState::Closing | NativeCoreDeviceState::Closed
                ) {
                    break;
                }
                let user = &user;
                let flow_prefix = &flow_prefix;
                let socket = &socket;
                let key = &key;
                device
                    .tracked_session(move |runtime| async move {
                        let cancel = runtime.connection_cancellation();
                        tokio::select! {
                            biased;
                            _ = cancel.cancelled() => {},
                            _ = async {
                                let responses = drain_udp_face_responses(
                                    &runtime,
                                    user,
                                    Some(flow_prefix),
                                    UDP_DRAIN_MAX_DATAGRAMS,
                                    UDP_DRAIN_MAX_WAIT,
                                )
                                .await;
                                for response in responses {
                                    if let Ok(packet) = seal_udp_packet(
                                        method,
                                        key,
                                        &response.source_endpoint,
                                        &response.payload,
                                    ) {
                                        let _ = socket.send_to(&packet, response.source).await;
                                    }
                                }
                            } => {},
                        }
                    })
                    .await;
            }
        });
    }

    let mut buffer = vec![0_u8; SHADOWSOCKS_UDP_BUFFER];
    loop {
        let received = tokio::select! {
            _ = wait_for_shutdown(&mut shutdown_rx) => break,
            Some(_) = drains.join_next(), if !drains.is_empty() => break,
            received = socket.recv_from(&mut buffer) => received,
        };
        let (read, client) = match received {
            Ok(pair) => pair,
            // One socket serves every client: what a receive reports ends
            // none of them.
            Err(error) => {
                crate::outbound::after_receive_error(&error).await;
                continue;
            }
        };
        let Some((user, target, payload)) = table.open_udp(&buffer[..read]) else {
            // No user key opened it: an auth failure the host alarms on. Bounded
            // (one packet) and counted; the packet is dropped, never answered, so
            // a public port cannot be turned into an amplifier.
            auth_failures.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        // No-wait relay: hand the datagram to its session actor and move straight
        // on, so a slow target never head-of-line-blocks the socket's other
        // clients. A routing/dial failure drops the datagram like any UDP loss.
        let datagram = UdpDatagram {
            flow_id: Some(shadowsocks_udp_flow_id(&user, client)),
            pump_queue: None,
            // An authenticated Shadowsocks server inbound's UDP associate.
            inbound: "udp-associate",
            user: Some(user),
            source: client,
            target,
            payload,
            process_name: None,
            process_path: None,
        };
        device
            .tracked_session(move |runtime| async move {
                let _ = send_udp_flow_datagram(&runtime, datagram).await;
            })
            .await;
    }
    drains.abort_all();
    while drains.join_next().await.is_some() {}
}

pub(super) async fn wait_for_shutdown(shutdown_rx: &mut watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    loop {
        if shutdown_rx.changed().await.is_err() || *shutdown_rx.borrow() {
            return;
        }
    }
}

/// A stable, non-empty flow id per `(user, client)` — `send_udp_flow_datagram`
/// requires one, and it keeps the client's flows addressable to `close_flow`.
fn shadowsocks_udp_flow_id(user: &Arc<str>, client: SocketAddr) -> String {
    format!("{}{client}", shadowsocks_udp_flow_prefix(user))
}

/// The prefix every flow id of this user shares, so a drain can scope itself
/// to this inbound rather than to every flow the user happens to own.
fn shadowsocks_udp_flow_prefix(user: &Arc<str>) -> String {
    format!("ss-udp/{user}/")
}
