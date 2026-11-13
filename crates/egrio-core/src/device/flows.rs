//! What comes into a device one at a time: a captured packet, a DNS query,
//! a TCP flow to route and relay, a UDP datagram and the responses to it.

use super::*;

impl NativeCoreDevice {
    /// Executes one non-TCP packet capture queue `queue` read (UDP relay, DNS
    /// capture, ICMP). Captured TCP goes to the TCP engine instead.
    pub(crate) async fn execute_packet(
        &self,
        queue: usize,
        packet: &CapturedPacket,
        answers: &crate::packet::AnswerSink,
    ) -> Result<crate::packet::PacketExecutionOutcome, String> {
        NativeCoreCaptureConfig::validate_mtu(self.capture_mtu())?;
        self.ensure_running()?;
        self.tracked_session(move |runtime| async move {
            let cancel = runtime.connection_cancellation();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err("packet execution cancelled by connection cutover".into()),
                result = crate::packet::execute_captured_packet(&runtime, queue, packet, answers) => result,
            }
        }).await
    }

    /// Feeds one captured packet the way the pump does, for tests that drive
    /// the device without a pump. DNS answers are discarded.
    #[cfg(test)]
    pub(crate) async fn ingest_packet(
        &self,
        bytes: Vec<u8>,
    ) -> Result<Option<crate::packet::PacketExecutionOutcome>, String> {
        NativeCoreCaptureConfig::validate_mtu(self.capture_mtu())?;
        self.ensure_running()?;
        if is_tcp_packet(&bytes) {
            self.inject_captured_tcp_packet(CapturedPacket::from_bytes(bytes));
            return Ok(None);
        }
        let (answers, _answers_back) = crate::packet::AnswerSink::channel();
        self.execute_packet(0, &CapturedPacket::from_bytes(bytes), &answers)
            .await
            .map(Some)
    }

    /// TCP segments and buffered UDP replies toward the client, for tests that
    /// drive the device without a pump.
    #[cfg(test)]
    pub(crate) async fn drain_pending_packets(&self) -> Result<Vec<Vec<u8>>, String> {
        self.ensure_running()?;
        let mut packets = self.drain_captured_tcp_packets(usize::MAX);
        packets.extend(
            drain_pending_udp_packets(
                &self.pinned_runtime(),
                0,
                crate::packet::PACKET_UDP_DRAIN_MAX_DATAGRAMS,
                None,
            )
            .await?
            .packets,
        );
        Ok(packets)
    }

    /// Drains the buffered upstream UDP replies of the flows capture queue
    /// `queue` opened.
    pub(super) async fn drain_pending_udp_packets(
        &self,
        queue: usize,
        max_datagrams: usize,
        train_mtu: Option<usize>,
    ) -> Result<crate::packet::UdpOutput, String> {
        self.ensure_running()?;
        drain_pending_udp_packets(&self.pinned_runtime(), queue, max_datagrams, train_mtu).await
    }

    pub async fn resolve_dns_query_payload(
        &self,
        payload: &[u8],
        process_name: Option<String>,
        process_path: Option<String>,
    ) -> Result<Vec<u8>, String> {
        self.ensure_running()?;
        self.tracked_session(move |runtime| async move {
            let cancel = runtime.connection_cancellation();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => Err("DNS query cancelled by connection cutover".into()),
                result = resolve_dns_query_payload(&runtime, payload, process_name, process_path) => result,
            }
        }).await
    }

    #[cfg(test)]
    pub(crate) fn route_tcp_flow(
        &self,
        client: TcpStream,
        target: NativeTcpFlowTarget,
    ) -> impl std::future::Future<Output = Result<NativeTcpFlowOutcome, NativeTcpFlowError>>
           + Send
           + 'static {
        let source = client.peer_addr().ok().map(|addr| addr.to_string());
        self.route_tcp_flow_io(client, source, target)
    }

    /// Feeds one duplex stream through the shared TCP dispatcher, as the
    /// TCP engine's accept path does for captured flows.
    #[cfg(test)]
    pub(crate) fn route_tcp_flow_io<S>(
        &self,
        client: S,
        source: Option<String>,
        target: NativeTcpFlowTarget,
    ) -> impl std::future::Future<Output = Result<NativeTcpFlowOutcome, NativeTcpFlowError>>
           + Send
           + 'static
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let running = self.ensure_running();
        self.tracked_session(move |runtime| async move {
            running.map_err(|_| {
                NativeTcpFlowError::new(
                    TcpFlowStage::Admission,
                    TcpFlowContext {
                        target: ConnectTarget {
                            host: target.host.clone(),
                            port: target.port,
                        }
                        .authority(),
                        ..Default::default()
                    },
                    TcpFlowFailure::Cancelled,
                )
            })?;
            let NativeTcpFlowTarget {
                host,
                port,
                process_name,
                process_path,
            } = target;
            let outcome = dispatch_accepted_stream(
                &runtime,
                source,
                AcceptedStream {
                    inbound: "test-flow",
                    user: None,
                    process: crate::attribution::ClientOwner::Known(
                        (process_name.is_some() || process_path.is_some()).then(|| {
                            Arc::new(ProcessInfo {
                                name: process_name,
                                path: process_path,
                            })
                        }),
                    ),
                    target: ConnectTarget { host, port },
                    io: Box::new(client),
                    replies: InboundReplyPlan::default(),
                    reset: None,
                },
            )
            .await?;
            if crate::rule_engine::is_reject_outbound(&outcome.outbound) {
                return Err(NativeTcpFlowError::new(
                    TcpFlowStage::Route,
                    TcpFlowContext {
                        target: outcome.target.clone(),
                        outbound: Some(outcome.outbound),
                        matched_rule: outcome.matched_rule,
                        matched_kind: outcome.matched_kind,
                        matched_payload: outcome.matched_payload,
                        ..Default::default()
                    },
                    TcpFlowFailure::RouteRejected,
                ));
            }
            Ok(outcome)
        })
    }

    /// Hands one datagram to its UDP session actor, as the packet executor
    /// does for captured UDP.
    #[cfg(test)]
    pub(crate) async fn send_udp_flow_datagram(
        &self,
        datagram: NativeUdpFlowDatagram,
    ) -> Result<NativeUdpFlowSendReport, String> {
        self.ensure_running()?;
        let connect_target = ConnectTarget {
            host: datagram.target.host.clone(),
            port: datagram.target.port,
        };
        let payload_len = datagram.payload.len();
        let outcome = udp::send_udp_flow_datagram(
            &self.pinned_runtime(),
            udp::UdpDatagram {
                flow_id: datagram.flow_id,
                pump_queue: None,
                inbound: "tun",
                user: None,
                source: datagram.source,
                target: connect_target.clone(),
                payload: datagram.payload,
                process_name: datagram.target.process_name,
                process_path: datagram.target.process_path,
            },
        )
        .await?;
        Ok(NativeUdpFlowSendReport {
            target: connect_target.authority(),
            bytes_sent: if outcome.enqueued { payload_len } else { 0 },
            enqueued: outcome.enqueued,
        })
    }

    #[cfg(test)]
    pub(crate) async fn drain_pending_udp_flow_responses(
        &self,
        max_datagrams: usize,
        max_wait: Duration,
    ) -> Result<Vec<NativeUdpFlowPendingDatagram>, String> {
        self.ensure_running()?;
        let datagrams =
            udp::drain_pending_udp_flow_responses(&self.pinned_runtime(), max_datagrams, max_wait)
                .await;
        Ok(datagrams
            .into_iter()
            .map(|datagram| NativeUdpFlowPendingDatagram {
                flow_id: datagram.flow_id,
                source_endpoint: datagram.source_endpoint.authority(),
                payload: datagram.payload,
            })
            .collect())
    }

    #[cfg(test)]
    pub(crate) fn close_udp_flow_sessions(&self, flow_id: &str) -> Result<usize, String> {
        udp::close_udp_flow_sessions(&self.pinned_runtime(), flow_id)
    }
}
