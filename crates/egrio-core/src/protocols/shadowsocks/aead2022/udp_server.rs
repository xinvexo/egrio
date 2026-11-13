//! Session-based SS2022 server UDP. The wire session survives client NAT
//! rebinding; Egrio's core flow keeps its original source and stable flow ID.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use shadowsocks::relay::udprelay::{
    crypto_io::{decrypt_client_payload, encrypt_server_payload},
    options::UdpSocketControlData,
};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinSet;

use super::replay::ReplayWindow;
use super::udp::SESSION_TTL;
use super::{from_address, to_address};
use crate::protocols::shadowsocks::acceptor::ShadowsocksUserTable;
use crate::udp::{drain_udp_face_responses, send_udp_flow_datagram, UdpDatagram};
use crate::{NativeCoreDevice, NativeCoreDeviceState};

const MAX_SESSIONS: usize = 1024;
static NEXT_LISTENER: AtomicU64 = AtomicU64::new(1);

struct Session {
    user_index: usize,
    client_id: u64,
    server_id: u64,
    next_packet: u64,
    source: SocketAddr,
    client: SocketAddr,
    replay: ReplayWindow,
    last_seen: Instant,
}

#[derive(Default)]
struct Sessions {
    entries: HashMap<String, Session>,
}

impl Sessions {
    fn admit(
        &mut self,
        flow_id: &str,
        user_index: usize,
        control: &UdpSocketControlData,
        client: SocketAddr,
    ) -> Option<SocketAddr> {
        let now = Instant::now();
        if !self.entries.contains_key(flow_id) && self.entries.len() >= MAX_SESSIONS {
            return None;
        }
        let session = self
            .entries
            .entry(flow_id.to_string())
            .or_insert_with(|| Session {
                user_index,
                client_id: control.client_session_id,
                server_id: rand::random(),
                next_packet: 0,
                source: client,
                client,
                replay: ReplayWindow::default(),
                last_seen: now,
            });
        if !session.replay.accept(control.packet_id) {
            return None;
        }
        session.client = client;
        session.last_seen = now;
        Some(session.source)
    }
}

pub(in crate::protocols::shadowsocks) async fn serve(
    socket: Arc<UdpSocket>,
    device: NativeCoreDevice,
    table: Arc<ShadowsocksUserTable>,
    auth_failures: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) {
    let prefix = format!(
        "ss2022-udp/{}/",
        NEXT_LISTENER.fetch_add(1, Ordering::Relaxed)
    );
    let sessions = Arc::new(Mutex::new(Sessions::default()));
    let mut tasks = JoinSet::new();
    for user in &table.users {
        tasks.spawn(drain(
            socket.clone(),
            device.clone(),
            table.clone(),
            sessions.clone(),
            prefix.clone(),
            user.name.clone(),
        ));
    }
    let mut buffer = vec![0; 65536];
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    loop {
        let received = tokio::select! {
            biased;
            _ = super::super::udp::wait_for_shutdown(&mut shutdown) => break,
            _ = tasks.join_next() => break,
            _ = sweep.tick() => {
                let now = Instant::now();
                let expired = {
                    let mut sessions = sessions.lock().expect("SS2022 sessions mutex");
                    let expired: Vec<_> = sessions.entries.iter()
                        .filter(|(_, session)| now.duration_since(session.last_seen) >= SESSION_TTL)
                        .map(|(id, _)| id.clone()).collect();
                    for id in &expired { sessions.entries.remove(id); }
                    expired
                };
                device.tracked_session(|runtime| async move {
                    for id in expired { runtime.udp_sessions().close_flows_with_prefix(&id); }
                }).await;
                continue;
            },
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
        // Every attempt needs the original ciphertext: decrypt mutates it.
        let opened = table.users.iter().enumerate().find_map(|(index, user)| {
            let mut packet = buffer[..read].to_vec();
            let (size, address, control) = decrypt_client_payload(
                &table.context,
                table.method(),
                &user.key,
                &mut packet,
                None,
            )
            .ok()?;
            Some((index, address, control?, packet[..size].to_vec()))
        });
        let Some((index, address, control, payload)) = opened else {
            auth_failures.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let flow_id = format!("{prefix}{index}/{:016x}/", control.client_session_id);
        let source = sessions
            .lock()
            .expect("SS2022 sessions mutex")
            .admit(&flow_id, index, &control, client);
        let Some(source) = source else { continue };
        let datagram = UdpDatagram {
            flow_id: Some(flow_id),
            pump_queue: None,
            inbound: "udp-associate",
            user: Some(table.users[index].name.clone()),
            source,
            target: from_address(address),
            payload,
            process_name: None,
            process_path: None,
        };
        device
            .tracked_session(|runtime| async move {
                let _ = send_udp_flow_datagram(&runtime, datagram).await;
            })
            .await;
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    device
        .tracked_session(|runtime| async move {
            runtime.udp_sessions().close_flows_with_prefix(&prefix);
        })
        .await;
}

async fn drain(
    socket: Arc<UdpSocket>,
    device: NativeCoreDevice,
    table: Arc<ShadowsocksUserTable>,
    sessions: Arc<Mutex<Sessions>>,
    prefix: String,
    user: Arc<str>,
) {
    let user = Some(user);
    loop {
        if matches!(
            device.status().state,
            NativeCoreDeviceState::Closing | NativeCoreDeviceState::Closed
        ) {
            return;
        }
        let table = &table;
        let socket = &socket;
        let sessions = &sessions;
        let prefix = &prefix;
        let user = &user;
        device.tracked_session(|runtime| async move {
            let cancel = runtime.connection_cancellation();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {},
                _ = async {
                    let responses = drain_udp_face_responses(&runtime, user, Some(prefix), 256, Duration::from_secs(1)).await;
                    for response in responses {
                        let Some(flow_id) = &response.flow_id else { continue };
                        let reply = {
                            let mut sessions = sessions.lock().expect("SS2022 sessions mutex");
                            sessions.entries.get_mut(flow_id).and_then(|session| {
                                let packet_id = session.next_packet;
                                session.next_packet = packet_id.checked_add(1)?;
                                let user = &table.users[session.user_index];
                                let mut control = UdpSocketControlData::default();
                                control.client_session_id = session.client_id;
                                control.server_session_id = session.server_id;
                                control.packet_id = packet_id;
                                let address = to_address(&response.source_endpoint).ok()?;
                                let mut packet = BytesMut::new();
                                encrypt_server_payload(&table.context, table.method(), &user.key, &address, &control, &response.payload, &mut packet);
                                Some((packet, session.client))
                            })
                        };
                        if let Some((packet, client)) = reply {
                            let _ = socket.send_to(&packet, client).await;
                        }
                    }
                } => {},
            }
        }).await;
    }
}
