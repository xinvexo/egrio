//! The DNS listener of one generation: answers each query through the Core's
//! resolver under the query limit, each pinning the snapshot current when it
//! arrives.

use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use super::state::{mark_listener_error, CoreSessionManagerInner};
use super::wait_for_shutdown;
use crate::device::NativeCoreDevice;
use crate::dns::resolver::resolve_dns_query_payload;

const NATIVE_CORE_DNS_UDP_BUFFER_BYTES: usize = 4096;

pub(super) async fn run_dns_listener(
    inner: Arc<Mutex<CoreSessionManagerInner>>,
    generation: u64,
    socket: Arc<UdpSocket>,
    device: NativeCoreDevice,
    query_limit: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut buffer = vec![0_u8; NATIVE_CORE_DNS_UDP_BUFFER_BYTES];
    let mut queries = JoinSet::new();
    loop {
        tokio::select! {
            _ = wait_for_shutdown(&mut shutdown_rx) => {
                break;
            }
            Some(_) = queries.join_next(), if !queries.is_empty() => {}
            received = socket.recv_from(&mut buffer) => {
                match received {
                    Ok((bytes_read, peer)) => {
                        let Some(query_permit) = acquire_dns_query_permit(&query_limit) else {
                            continue;
                        };
                        let query = buffer[..bytes_read].to_vec();
                        let socket = socket.clone();
                        // Each query pins the snapshot current at receive
                        // time, so DNS policy swaps take effect immediately
                        // while fake-IP mappings survive in shared state.
                        queries.spawn(device.tracked_session(move |runtime| async move {
                            let _query_permit = query_permit;
                            let cancel = runtime.connection_cancellation();
                            tokio::select! {
                                biased;
                                _ = cancel.cancelled() => {},
                                _ = async {
                                    if let Ok(response) = resolve_dns_query_payload(&runtime, &query, None, None).await {
                                        let _ = socket.send_to(&response, peer).await;
                                    }
                                } => {},
                            }
                        }));
                    }
                    // The socket serves every client of the listener and
                    // outlives what one receive reports. An event about one
                    // datagram -- the client closed its port before its
                    // answer came -- is not the listener's error to show.
                    Err(error) => {
                        if !crate::outbound::is_datagram_event(&error) {
                            mark_listener_error(&inner, generation, "DNS listener receive", &error);
                        }
                        crate::outbound::after_receive_error(&error).await;
                    }
                }
            }
        }
    }
    queries.abort_all();
    while queries.join_next().await.is_some() {}
}

fn acquire_dns_query_permit(query_limit: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(query_limit).try_acquire_owned().ok()
}
