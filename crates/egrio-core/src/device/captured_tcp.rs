//! The captured TCP flows of a device: the engine of each capture queue,
//! the packets injected into it, the streams it accepts, and the DNS it
//! serves over TCP on the tunnel's own resolver address.

use super::*;

impl NativeCoreDevice {
    /// Capture queue `queue`'s TCP engine, creating it and its accept loop on
    /// first use. Must run inside a tokio runtime — true for every packet
    /// entrypoint; the accept loop and the relays of the engine's flows run
    /// on the caller's.
    ///
    /// Returns `None` once the device is closing or closed. Creation is
    /// otherwise a resurrection: `close()` clears the engines exactly once, so
    /// an engine created after that point would never be shut down, and its
    /// accept loop would run for the rest of the device's life, silently,
    /// since the closed registry refuses every flow it accepts.
    pub(super) fn ensure_packet_tcp(&self, queue: PacketQueue) -> Option<Arc<PacketTcp>> {
        if NativeCoreCaptureConfig::validate_mtu(self.capture_mtu()).is_err()
            || queue.index >= queue.count
        {
            return None;
        }
        let mut engines = self
            .inner
            .packet_tcp
            .lock()
            .expect("native core packet TCP engines");
        if let Some(existing) = engines.get(queue) {
            return Some(existing);
        }
        // Checked under the engines lock, and `close()` clears the engines
        // under that same lock after publishing `Closing`, so the two cannot
        // interleave into a post-close create.
        if matches!(
            *self.inner.state.lock().expect("native core device state"),
            NativeCoreDeviceState::Closing | NativeCoreDeviceState::Closed
        ) {
            return None;
        }
        // The engines of a capture with another number of queues end, with
        // their flows: those flows' packets went with that capture.
        let retired = if engines.count == queue.count {
            Vec::new()
        } else {
            let retired = engines.take_all();
            engines.count = queue.count;
            engines.queues.resize_with(queue.count, || None);
            retired
        };
        let share = (queue.count > 1).then(|| QueueShare {
            queue: queue.index,
            holders: Arc::clone(
                engines
                    .holders
                    .get_or_insert_with(|| Arc::new(FlowHolders::new(queue.count))),
            ),
        });
        let (accept_tx, mut accept_rx) = tokio::sync::mpsc::unbounded_channel();
        let engine = TcpEngine::new(
            self.inner.snapshot.load().capture.mtu,
            accept_tx,
            Arc::clone(&self.inner.packet_tcp_active),
            share,
        );
        let tcp = Arc::new(PacketTcp {
            wake: engine.wake(),
            engine: Mutex::new(engine),
            forwarded: Mutex::default(),
        });
        // The loop belongs to the engine, not to a route epoch: it ends when
        // the engine goes (its channel closes) or the device does. Each flow
        // pins the snapshot current when the engine hands it over, so one
        // accepted after a policy change routes under the new policy.
        let device = Arc::downgrade(&self.inner);
        let lifetime = self.inner.sessions.lifetime.clone();
        tokio::spawn(async move {
            loop {
                let stream = tokio::select! {
                    biased;
                    _ = lifetime.cancelled() => break,
                    stream = accept_rx.recv() => match stream { Some(stream) => stream, None => break },
                };
                let Some(inner) = device.upgrade() else {
                    break;
                };
                let runtime =
                    NativeCoreRuntime::pinned(inner.snapshot.load_full(), inner.sessions.clone())
                        .joining_epoch();
                drop(inner);
                tokio::spawn(Self::serve_captured_tcp_stream(runtime, stream));
            }
        });
        engines.queues[queue.index] = Some(Arc::clone(&tcp));
        // Under the engines lock, which forwarding takes, so a flow placed
        // on this queue finds its engine.
        if let Some(holders) = &engines.holders {
            holders.open(queue.index);
        }
        drop(engines);
        for old in retired {
            old.engine().shutdown();
        }
        Some(tcp)
    }

    /// Hands one captured TCP packet to the engine of a capture with one
    /// queue. The packet's process attribution rides along for the SYN, where
    /// the accepted stream adopts it.
    #[cfg(test)]
    pub(crate) fn inject_captured_tcp_packet(&self, packet: CapturedPacket) {
        self.inject_captured_tcp_packets(PacketQueue::ONLY, std::iter::once((packet, None)));
    }

    /// Hands TCP packets capture queue `queue` read to its engine under one
    /// lock, each with the queue its flow should go to if it is new and one
    /// suits it best; segments of flows another queue's engine holds go on to
    /// it.
    pub(crate) fn inject_captured_tcp_packets(
        &self,
        queue: PacketQueue,
        packets: impl IntoIterator<Item = (CapturedPacket, Option<usize>)>,
    ) {
        // A closed device drops the packets: their flows would be refused by
        // the closed registry anyway.
        let Some(tcp) = self.ensure_packet_tcp(queue) else {
            return;
        };
        let now = std::time::Instant::now();
        let foreign = {
            let mut engine = tcp.engine();
            for (packet, prefer) in packets {
                engine.on_packet(
                    bytes::Bytes::from(packet.bytes),
                    packet.process,
                    prefer,
                    now,
                );
            }
            engine.take_foreign()
        };
        self.forward_tcp(foreign);
    }

    /// Hands segments to the engines holding their flows and wakes their
    /// pumps. A segment whose engine has ended is dropped with it.
    pub(super) fn forward_tcp(&self, foreign: Vec<ForeignSegment>) {
        if foreign.is_empty() {
            return;
        }
        let engines = self
            .inner
            .packet_tcp
            .lock()
            .expect("native core packet TCP engines");
        for segment in foreign {
            if let Some(Some(tcp)) = engines.queues.get(segment.queue) {
                tcp.forwarded
                    .lock()
                    .expect("captured TCP forwarded segments")
                    .push(segment.packet, segment.process);
                tcp.wake.notify.notify_one();
            }
        }
    }

    /// One accepted captured flow, end to end. Virtual-DNS targets are served
    /// by the DNS engine over the stream; everything else goes through the
    /// same enrich → route → dial → relay pipeline as any inbound listener,
    /// so the session registry (connection table, kill switch and byte
    /// accounting) covers TUN flows with no parallel
    /// bookkeeping.
    fn serve_captured_tcp_stream(
        runtime: NativeCoreRuntime,
        mut stream: CapturedTcpStream,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
        async move {
            let target_addr = stream.target_addr();
            let hijack = &runtime.capture().dns_hijack;
            if hijack.captures_tcp_destination(target_addr.ip(), Some(target_addr.port())) {
                let process = stream.process().cloned();
                // Failures drop the stream; the client sees the close and retries.
                let cancel = runtime.connection_cancellation();
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {},
                    _ = serve_captured_tcp_dns(&runtime, &mut stream, process) => {},
                }
                return;
            }
            // A fake-range destination with no live mapping is a stale resolver
            // cache from an earlier capture session, and the capture
            // interface's own subnet is never dialed out the physical uplink:
            // reset the client at once instead.
            let destination_ip = target_addr.ip();
            if runtime.capture().is_interface_destination(destination_ip)
                || (runtime.fake_dns_domain_for_ip(destination_ip).is_none()
                    && runtime.is_stale_fake_target(destination_ip))
            {
                stream.reset_handle().reset();
                return;
            }

            let process = stream.take_owner();
            let source = stream.client_addr();
            let reset = stream.reset_handle();
            let accepted = AcceptedStream {
                inbound: "tun",
                user: None,
                process,
                target: ConnectTarget {
                    // Keep the capture destination for diagnostics. The shared
                    // enrich stage recovers a fake-IP domain before routing
                    // and dialing.
                    host: destination_ip.to_string(),
                    port: target_addr.port(),
                },
                io: Box::new(stream),
                replies: InboundReplyPlan::default(),
                // A flow refused, undialable or ended by Core is reset, as a
                // server refusing or aborting the connection would.
                reset: Some(Box::new(move || reset.reset())),
            };
            // An upstream close or failure drops the stream, which flushes
            // and FINs toward the client.
            let _ = dispatch_accepted_stream(&runtime, Some(source.to_string()), accepted).await;
        }
    }

    /// Takes out every engine and resets their flows at once, whoever still
    /// holds them.
    pub(super) fn retire_packet_tcp(&self) {
        let retired = self
            .inner
            .packet_tcp
            .lock()
            .expect("native core packet TCP engines")
            .take_all();
        for tcp in retired {
            tcp.engine().shutdown();
        }
    }

    /// Drives the engine once and takes up to `max_packets` of its segments
    /// as whole packets, without waiting: relay events and due timers first.
    #[cfg(test)]
    pub(super) fn drain_captured_tcp_packets(&self, max_packets: usize) -> Vec<Vec<u8>> {
        let Some(tcp) = self.packet_tcp_engine() else {
            return Vec::new();
        };
        let now = std::time::Instant::now();
        let mut engine = tcp.engine();
        engine.attend(now);
        engine.on_timers(now);
        let mut packets = Vec::new();
        engine.emit(now, max_packets, &mut |segment| {
            packets.push(segment.to_vec())
        });
        packets
    }

    /// The engine of a capture with one queue, if it has been made.
    #[cfg(test)]
    pub(super) fn packet_tcp_engine(&self) -> Option<Arc<PacketTcp>> {
        self.inner
            .packet_tcp
            .lock()
            .expect("native core packet TCP engines")
            .get(PacketQueue::ONLY)
    }

    /// How many queues' engines are up.
    #[cfg(test)]
    pub(super) fn packet_tcp_engines_up(&self) -> usize {
        self.inner
            .packet_tcp
            .lock()
            .expect("native core packet TCP engines")
            .queues
            .iter()
            .flatten()
            .count()
    }
}

/// Serves a captured TCP/53 flow addressed to a virtual DNS target: framed
/// queries (RFC 1035 §4.2.2 length prefix) answer through the core DNS engine
/// over the same stream, so DNS-over-TCP clients work without any upstream
/// dial.
async fn serve_captured_tcp_dns(
    runtime: &NativeCoreRuntime,
    stream: &mut CapturedTcpStream,
    process: Option<Arc<ProcessInfo>>,
) -> Result<(), String> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 2048];
    loop {
        while let Some(query) = pop_framed_tcp_dns_query(&mut buffer)? {
            let response = resolve_dns_query_payload_for_transport(
                runtime,
                &query,
                process.as_ref().and_then(|process| process.name.clone()),
                process.as_ref().and_then(|process| process.path.clone()),
                DnsQueryTransport::Tcp,
            )
            .await?;
            let framed = frame_tcp_dns_response(&response)?;
            stream
                .write_all(&framed)
                .await
                .map_err(|error| format!("TCP DNS response write failed: {error}"))?;
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("TCP DNS query read failed: {error}"))?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn pop_framed_tcp_dns_query(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, String> {
    if buffer.len() < 2 {
        return Ok(None);
    }
    let query_len = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    if query_len == 0 {
        return Err("TCP DNS query has an empty length prefix".into());
    }
    if buffer.len() < 2 + query_len {
        return Ok(None);
    }
    let query = buffer[2..2 + query_len].to_vec();
    buffer.drain(0..2 + query_len);
    Ok(Some(query))
}

fn frame_tcp_dns_response(response: &[u8]) -> Result<Vec<u8>, String> {
    let response_len = u16::try_from(response.len())
        .map_err(|_| format!("TCP DNS response exceeds 65535 bytes: {}", response.len()))?;
    let mut framed = Vec::with_capacity(2 + response.len());
    framed.extend_from_slice(&response_len.to_be_bytes());
    framed.extend_from_slice(response);
    Ok(framed)
}
