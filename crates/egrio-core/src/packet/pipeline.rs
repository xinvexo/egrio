use serde::Serialize;

use super::frame::{parse_packet_flow, CapturedPacket, IpTransportProtocol, PacketFlow};
use super::icmp::EchoRequest;
use crate::capture::NativeCoreDnsHijackMode;
use crate::rule_engine::{RouteDecision, RouteMatchInput, RouteMatchKind};
use crate::runtime::NativeCoreRuntime;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PacketCoreAction {
    /// TCP classifier vocabulary; captured TCP itself routes per flow at
    /// the TCP engine's accept, never per packet.
    DirectTcp,
    DirectUdp,
    DnsCapture,
    ProxyTcp,
    ProxyUdp,
    /// An ICMP echo request to a fake-range destination, answered locally:
    /// the block is virtual, so there is no host behind it.
    IcmpEchoReply,
    /// An ICMP echo request routed DIRECT, sent from an ICMP datagram socket
    /// on the physical uplink; its reply comes back later.
    IcmpEchoRelay,
    /// Any other ICMP, dropped and counted: echo cannot travel through a
    /// proxy, and other messages are not relayed.
    IcmpDrop,
    /// A multicast or broadcast destination a point-to-point tunnel cannot
    /// relay (mDNS/LLMNR/SSDP over 224.0.0.0/4 or ff00::/8, a 255.255.255.255
    /// broadcast, or an address in the capture interface's own subnet such as
    /// its directed broadcast); dropped and counted so it is not relayed out a
    /// unicast egress socket that would re-capture its own echo into a flood or
    /// send it through the physical uplink.
    MulticastDrop,
    Reject,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct PacketPipelineOutcome {
    pub action: PacketCoreAction,
    pub outbound: String,
    pub matched_rule: Option<String>,
    pub matched_kind: Option<RouteMatchKind>,
    pub matched_payload: Option<String>,
    pub no_resolve: bool,
    pub destination_ip: String,
    pub destination_host: Option<String>,
    pub destination_port: Option<u16>,
    pub transport: String,
    pub reason: Option<String>,
    pub packet_bytes: usize,
}

fn transport_network(flow: &PacketFlow) -> Option<crate::rule_engine::TransportNetwork> {
    match flow.protocol {
        IpTransportProtocol::Tcp => Some(crate::rule_engine::TransportNetwork::Tcp),
        IpTransportProtocol::Udp => Some(crate::rule_engine::TransportNetwork::Udp),
        _ => None,
    }
}

pub(crate) fn process_captured_packet(
    runtime: &NativeCoreRuntime,
    packet: &CapturedPacket,
) -> Result<PacketPipelineOutcome, String> {
    let flow = parse_packet_flow(&packet.bytes).map_err(|error| error.to_string())?;
    let destination_host = runtime.fake_dns_domain_for_ip(flow.destination_ip);
    // An echo the rules send DIRECT is relayed over the physical uplink where
    // the platform has ICMP datagram sockets, to the name's address when it
    // was sent to a fake IP. Any other echo to the fake-IP range is answered
    // locally: there is no host behind it, and echo cannot go through a
    // proxy. Other ICMP is not relayed: dropped and counted, as is echo to a
    // real address routed through a proxy.
    if flow.protocol == IpTransportProtocol::Icmp {
        let echo = EchoRequest::parse(&packet.bytes).is_some();
        let (action, outbound, reason) = if echo
            && runtime.egress().relays_echo()
            && routes_echo_direct(runtime, &flow, destination_host.as_deref(), packet)
        {
            (
                PacketCoreAction::IcmpEchoRelay,
                "DIRECT",
                "an echo routed DIRECT is relayed over the physical uplink",
            )
        } else if echo && runtime.is_fake_range_target(flow.destination_ip) {
            (
                PacketCoreAction::IcmpEchoReply,
                "LOCAL",
                "an echo to a fake-range target that is not routed DIRECT is answered locally",
            )
        } else {
            (
                PacketCoreAction::IcmpDrop,
                "DROP",
                "only echo routed DIRECT or to a fake-range target is relayed",
            )
        };
        return Ok(PacketPipelineOutcome {
            action,
            outbound: outbound.into(),
            matched_rule: None,
            matched_kind: None,
            matched_payload: None,
            no_resolve: false,
            destination_ip: flow.destination_ip.to_string(),
            destination_host,
            destination_port: None,
            transport: transport_name(flow.protocol).into(),
            reason: Some(reason.into()),
            packet_bytes: packet.bytes.len(),
        });
    }
    // A fake-range destination with no live mapping is a stale resolver
    // cache from a previous capture session; reject it fast instead of
    // relaying toward an address that never routes (or belongs to another
    // domain by now). DNS capture stays ahead of this: hijacked queries are
    // answered by the engine no matter what address they were aimed at.
    if destination_host.is_none()
        && dns_hijack_reason(runtime, &flow).is_none()
        && runtime.is_stale_fake_target(flow.destination_ip)
    {
        return Ok(PacketPipelineOutcome {
            action: PacketCoreAction::Reject,
            outbound: "REJECT".into(),
            matched_rule: None,
            matched_kind: None,
            matched_payload: None,
            no_resolve: false,
            destination_ip: flow.destination_ip.to_string(),
            destination_host: None,
            destination_port: flow.destination_port,
            transport: transport_name(flow.protocol).into(),
            reason: Some("stale fake-IP target has no mapping in this capture session".into()),
            packet_bytes: packet.bytes.len(),
        });
    }
    // Multicast and limited broadcast are non-unicast, link-local traffic a
    // point-to-point tunnel cannot relay: forwarding mDNS/LLMNR/SSDP
    // (224.0.0.0/4, ff00::/8) or a 255.255.255.255 broadcast out a unicast
    // egress socket re-captures its own echo, which on a busy LAN spirals into a
    // flood (mDNS alone drove tens of thousands of relayed datagrams per second
    // on a multi-adapter host). Drop and count them, like non-echo ICMP.
    // The capture interface's own subnet is just as local: its directed
    // broadcast (Windows sends NetBIOS name queries there) must not leave
    // through the physical uplink. DNS aimed at an in-subnet virtual resolver
    // is still answered.
    if flow.destination_ip.is_multicast()
        || matches!(flow.destination_ip, std::net::IpAddr::V4(address) if address.is_broadcast())
        || (runtime
            .capture()
            .is_interface_destination(flow.destination_ip)
            && dns_hijack_reason(runtime, &flow).is_none())
    {
        return Ok(PacketPipelineOutcome {
            action: PacketCoreAction::MulticastDrop,
            outbound: "DROP".into(),
            matched_rule: None,
            matched_kind: None,
            matched_payload: None,
            no_resolve: false,
            destination_ip: flow.destination_ip.to_string(),
            destination_host,
            destination_port: flow.destination_port,
            transport: transport_name(flow.protocol).into(),
            reason: Some("multicast/broadcast is not relayed over a point-to-point tunnel".into()),
            packet_bytes: packet.bytes.len(),
        });
    }
    // A mapped fake IP is no address of the destination; the rules see its
    // name. The packet stage never waits on DNS: a datagram whose IP rules
    // ask for the name's address is left to the UDP session, which resolves
    // it and routes.
    let (route, address_pending) = runtime.route_unresolved(&RouteMatchInput {
        host: destination_host.clone(),
        destination_ip: destination_host.is_none().then_some(flow.destination_ip),
        destination_port: flow.destination_port,
        source_ip: Some(flow.source_ip),
        source_port: flow.source_port,
        network: transport_network(&flow),
        process_name: packet.process_name(),
        process_path: packet.process_path(),
    });

    Ok(packet_action(
        runtime,
        packet.bytes.len(),
        flow,
        destination_host,
        route,
        address_pending,
    ))
}

/// Whether the rules send an echo DIRECT: to the name a fake IP stands for,
/// or to a unicast address outside the capture interface's own subnet (the
/// rest stays local, as for UDP). A fake IP without a name has no target.
fn routes_echo_direct(
    runtime: &NativeCoreRuntime,
    flow: &PacketFlow,
    host: Option<&str>,
    packet: &CapturedPacket,
) -> bool {
    let destination = flow.destination_ip;
    if host.is_none()
        && (runtime.is_fake_range_target(destination)
            || destination.is_multicast()
            || destination.is_unspecified()
            || matches!(destination, std::net::IpAddr::V4(address) if address.is_broadcast())
            || runtime.capture().is_interface_destination(destination))
    {
        return false;
    }
    let (route, _) = runtime.route_unresolved(&RouteMatchInput {
        host: host.map(str::to_owned),
        destination_ip: host.is_none().then_some(destination),
        destination_port: None,
        source_ip: Some(flow.source_ip),
        source_port: None,
        network: None,
        process_name: packet.process_name(),
        process_path: packet.process_path(),
    });
    runtime
        .resolve_outbound(
            &route.outbound,
            &crate::target::ConnectTarget {
                host: host.map_or_else(|| destination.to_string(), str::to_owned),
                port: 0,
            },
        )
        .is_some_and(|resolved| resolved.connector.is_direct())
}

fn packet_action(
    runtime: &NativeCoreRuntime,
    packet_bytes: usize,
    flow: PacketFlow,
    destination_host: Option<String>,
    route: RouteDecision,
    address_pending: bool,
) -> PacketPipelineOutcome {
    let outbound = route.outbound.clone();
    let (action, reason) = if let Some(reason) = dns_hijack_reason(runtime, &flow) {
        (PacketCoreAction::DnsCapture, Some(reason))
    } else if address_pending && is_udp_flow(&flow) {
        (
            PacketCoreAction::ProxyUdp,
            Some("the UDP session routes once the destination name resolves".into()),
        )
    } else if crate::rule_engine::is_reject_outbound(&route.outbound) {
        (
            PacketCoreAction::Reject,
            Some("route selected reject outbound".into()),
        )
    } else {
        // Concrete outbound names take the allocation-free lookup this
        // per-packet path always had; only a route that names a policy group
        // pays for building the dial target (LoadBalance hashes it for
        // per-target stickiness) and resolving through group state.
        let connector = match runtime.outbound_table().get(&route.outbound) {
            Some(connector) => Some(connector.as_ref()),
            None => {
                let connect_target = crate::target::ConnectTarget {
                    host: destination_host
                        .clone()
                        .unwrap_or_else(|| flow.destination_ip.to_string()),
                    port: flow.destination_port.unwrap_or(0),
                };
                runtime
                    .resolve_outbound(&route.outbound, &connect_target)
                    .map(|resolved| resolved.connector)
            }
        };
        match connector {
            Some(connector) if connector.is_direct() && is_tcp_flow(&flow) => {
                (PacketCoreAction::DirectTcp, None)
            }
            Some(connector) if connector.is_direct() && is_udp_flow(&flow) => {
                (PacketCoreAction::DirectUdp, None)
            }
            Some(connector) if connector.is_direct() => (
                PacketCoreAction::Unsupported,
                Some(format!(
                    "transport {:?} is not directly relayed yet",
                    flow.protocol
                )),
            ),
            Some(connector) if is_tcp_flow(&flow) && connector.supports_tcp() => {
                (PacketCoreAction::ProxyTcp, None)
            }
            Some(connector) if is_udp_flow(&flow) && connector.supports_udp() => {
                (PacketCoreAction::ProxyUdp, None)
            }
            Some(_) if is_tcp_flow(&flow) || is_udp_flow(&flow) => (
                PacketCoreAction::Unsupported,
                Some(format!(
                    "outbound '{}' does not support {:?} packets",
                    route.outbound, flow.protocol
                )),
            ),
            Some(_) => (
                PacketCoreAction::Unsupported,
                Some(format!("transport {:?} is not proxied yet", flow.protocol)),
            ),
            None => (
                PacketCoreAction::Unsupported,
                Some(format!("outbound '{}' is not implemented", route.outbound)),
            ),
        }
    };

    PacketPipelineOutcome {
        action,
        outbound,
        matched_rule: route.matched_rule,
        matched_kind: route.matched_kind,
        matched_payload: route.matched_payload,
        no_resolve: route.no_resolve,
        destination_ip: flow.destination_ip.to_string(),
        destination_host,
        destination_port: flow.destination_port,
        transport: transport_name(flow.protocol).into(),
        reason,
        packet_bytes,
    }
}

fn is_tcp_flow(flow: &PacketFlow) -> bool {
    matches!(flow.protocol, IpTransportProtocol::Tcp)
}

fn is_udp_flow(flow: &PacketFlow) -> bool {
    matches!(flow.protocol, IpTransportProtocol::Udp)
}

fn dns_hijack_reason(runtime: &NativeCoreRuntime, flow: &PacketFlow) -> Option<String> {
    let captured = match flow.protocol {
        IpTransportProtocol::Udp => runtime
            .capture()
            .dns_hijack
            .captures_udp_destination(flow.destination_ip, flow.destination_port),
        IpTransportProtocol::Tcp => runtime
            .capture()
            .dns_hijack
            .captures_tcp_destination(flow.destination_ip, flow.destination_port),
        IpTransportProtocol::Icmp | IpTransportProtocol::Other(_) => false,
    };
    if !captured {
        return None;
    }

    match runtime.capture().dns_hijack.mode {
        NativeCoreDnsHijackMode::Disabled => None,
        NativeCoreDnsHijackMode::UdpPort => Some(format!(
            "captured DNS query packet on UDP port {}",
            runtime.capture().dns_hijack.udp_port
        )),
        NativeCoreDnsHijackMode::UdpPortWithVirtualTcpTargets => Some(format!(
            "captured DNS query packet over {} on port {}",
            transport_name(flow.protocol),
            runtime.capture().dns_hijack.udp_port,
        )),
        NativeCoreDnsHijackMode::VirtualDnsTargets => Some(format!(
            "captured DNS query packet over {} for virtual DNS target {}",
            transport_name(flow.protocol),
            flow.destination_ip
        )),
    }
}

fn transport_name(protocol: IpTransportProtocol) -> &'static str {
    match protocol {
        IpTransportProtocol::Tcp => "tcp",
        IpTransportProtocol::Udp => "udp",
        IpTransportProtocol::Icmp => "icmp",
        IpTransportProtocol::Other(_) => "other",
    }
}

#[cfg(test)]
fn build_ipv4_packet(
    protocol: IpTransportProtocol,
    source_ip: [u8; 4],
    destination_ip: [u8; 4],
    source_port: u16,
    destination_port: u16,
) -> Vec<u8> {
    let protocol = match protocol {
        IpTransportProtocol::Tcp => 6,
        IpTransportProtocol::Udp => 17,
        IpTransportProtocol::Icmp => 1,
        IpTransportProtocol::Other(value) => value,
    };
    let mut packet = vec![0_u8; 24];
    let packet_len = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source_ip);
    packet[16..20].copy_from_slice(&destination_ip);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use serde_json::json;

    use super::*;
    use crate::profile::{ProxyNode, ProxyProtocol, RouteRule, RuleKind, RuntimeProfile};
    use crate::{NativeCoreCaptureConfig, NativeCoreDnsHijackConfig};

    #[test]
    fn routes_ipv4_tcp_packet_to_proxy_action() {
        let runtime =
            NativeCoreRuntime::compile(&proxy_profile("Proxy", ProxyProtocol::Http, json!({})));
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Tcp,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            49152,
            443,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::ProxyTcp);
        assert_eq!(outcome.outbound, "Proxy");
        assert_eq!(outcome.transport, "tcp");
        assert_eq!(outcome.destination_ip, "1.1.1.1");
        assert_eq!(outcome.destination_port, Some(443));
    }

    #[test]
    fn rejects_packet_when_rule_selects_reject() {
        let mut profile = RuntimeProfile::new("packet-reject");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "REJECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [8, 8, 8, 8],
            53000,
            12345,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::Reject);
        assert_eq!(outcome.outbound, "REJECT");
    }

    #[test]
    fn drops_multicast_udp_ahead_of_routing() {
        // mDNS to 224.0.0.251:5353 must never reach the outbound path: a proxy
        // profile would otherwise route it, but multicast is dropped ahead of
        // routing so relaying it out a unicast egress can't loop it back in.
        let runtime =
            NativeCoreRuntime::compile(&proxy_profile("Proxy", ProxyProtocol::Http, json!({})));
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [224, 0, 0, 251],
            5353,
            5353,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is classified");

        assert_eq!(outcome.action, PacketCoreAction::MulticastDrop);
        assert_eq!(outcome.outbound, "DROP");
        assert_eq!(outcome.transport, "udp");
    }

    #[test]
    fn drops_limited_broadcast_udp_ahead_of_routing() {
        let runtime =
            NativeCoreRuntime::compile(&proxy_profile("Proxy", ProxyProtocol::Http, json!({})));
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [255, 255, 255, 255],
            50000,
            9999,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is classified");

        assert_eq!(outcome.action, PacketCoreAction::MulticastDrop);
        assert_eq!(outcome.outbound, "DROP");
    }

    #[test]
    fn marks_udp_unsupported_for_a_global_http_proxy_outbound() {
        let mut profile = proxy_profile("Proxy", ProxyProtocol::Http, json!({}));
        profile.traffic_policy_mode = crate::profile::TrafficPolicyMode::Global;
        profile.global_outbound = Some("Proxy".into());
        let runtime = NativeCoreRuntime::compile(&profile);
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            53000,
            12345,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::Unsupported);
        assert!(outcome
            .reason
            .as_deref()
            .expect("reason")
            .contains("does not support"));
    }

    #[test]
    fn a_udp_flow_skips_a_rule_whose_outbound_has_udp_off() {
        let udp_packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            53000,
            443,
        ));
        let tcp_packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Tcp,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            53000,
            443,
        ));
        let ss = json!({"cipher": "aes-128-gcm", "password": "secret"});
        for (options, udp_action, udp_outbound) in [
            // Clash's default: no `udp` means the node carries none, so the
            // flow moves past MATCH and ends DIRECT.
            (ss.clone(), PacketCoreAction::DirectUdp, "DIRECT"),
            (
                json!({"cipher": "aes-128-gcm", "password": "secret", "udp": true}),
                PacketCoreAction::ProxyUdp,
                "Proxy",
            ),
        ] {
            let runtime = NativeCoreRuntime::compile(&proxy_profile(
                "Proxy",
                ProxyProtocol::Shadowsocks,
                options,
            ));
            let udp = process_captured_packet(&runtime, &udp_packet).expect("UDP is routed");
            assert_eq!(
                (udp.action, udp.outbound.as_str()),
                (udp_action, udp_outbound)
            );
            let tcp = process_captured_packet(&runtime, &tcp_packet).expect("TCP is routed");
            assert_eq!(
                (tcp.action, tcp.outbound.as_str()),
                (PacketCoreAction::ProxyTcp, "Proxy")
            );
        }
    }

    #[test]
    fn marks_udp_dns_as_capture_before_udp_outbound_capability() {
        let runtime =
            NativeCoreRuntime::compile(&proxy_profile("Proxy", ProxyProtocol::Http, json!({})));
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [198, 18, 0, 1],
            53000,
            53,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::DnsCapture);
        assert_eq!(outcome.transport, "udp");
    }

    #[test]
    fn drops_traffic_into_the_capture_subnet_but_answers_its_dns() {
        // The Wintun /30: Windows sends NetBIOS name queries to its directed
        // broadcast, which DIRECT would send out the physical uplink.
        let runtime = NativeCoreRuntime::compile_with_egress_and_capture(
            &RuntimeProfile::new("capture-subnet"),
            crate::NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::default().with_interface_networks([
                crate::NativeCoreInterfaceNetwork::new(Ipv4Addr::new(10, 255, 255, 1), 30),
            ]),
        );
        let classify = |destination: [u8; 4], port: u16| {
            let packet = CapturedPacket::from_bytes(build_ipv4_packet(
                IpTransportProtocol::Udp,
                [10, 255, 255, 1],
                destination,
                137,
                port,
            ));
            process_captured_packet(&runtime, &packet)
                .expect("packet is classified")
                .action
        };

        assert_eq!(
            classify([10, 255, 255, 3], 137),
            PacketCoreAction::MulticastDrop
        );
        assert_eq!(
            classify([10, 255, 255, 2], 8080),
            PacketCoreAction::MulticastDrop
        );
        assert_eq!(
            classify([10, 255, 255, 2], 53),
            PacketCoreAction::DnsCapture
        );
        assert_eq!(
            classify([10, 255, 255, 4], 137),
            PacketCoreAction::DirectUdp
        );
    }

    #[test]
    fn virtual_dns_hijack_captures_configured_windows_dns_target() {
        let runtime = NativeCoreRuntime::compile_with_egress_and_capture(
            &proxy_profile("Proxy", ProxyProtocol::Http, json!({})),
            crate::NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::with_dns_hijack(
                NativeCoreDnsHijackConfig::capture_virtual_dns_targets([IpAddr::V4(
                    Ipv4Addr::new(10, 255, 255, 2),
                )]),
            ),
        );
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [10, 255, 255, 2],
            53000,
            53,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::DnsCapture);
        assert_eq!(outcome.destination_ip, "10.255.255.2");
        assert!(outcome
            .reason
            .as_deref()
            .expect("reason")
            .contains("virtual DNS target"));
    }

    #[test]
    fn virtual_dns_hijack_does_not_capture_other_udp_53_targets() {
        // Route via DIRECT so the packet still takes a real UDP-capable path
        // (DirectUdp) rather than DNS capture: the point is that an
        // unconfigured :53 target is not hijacked, not which outbound carries
        // it.
        let mut profile = RuntimeProfile::new("virtual-dns-direct");
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::compile_with_egress_and_capture(
            &profile,
            crate::NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::with_dns_hijack(
                NativeCoreDnsHijackConfig::capture_virtual_dns_targets([IpAddr::V4(
                    Ipv4Addr::new(10, 255, 255, 2),
                )]),
            ),
        );
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [1, 1, 1, 1],
            53000,
            53,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::DirectUdp);
        assert_eq!(outcome.destination_ip, "1.1.1.1");
    }

    #[test]
    fn virtual_dns_hijack_captures_configured_tcp_dns_target() {
        let runtime = NativeCoreRuntime::compile_with_egress_and_capture(
            &proxy_profile("Proxy", ProxyProtocol::Http, json!({})),
            crate::NativeCoreEgressConfig::default(),
            NativeCoreCaptureConfig::with_dns_hijack(
                NativeCoreDnsHijackConfig::capture_virtual_dns_targets([IpAddr::V4(
                    Ipv4Addr::new(10, 255, 255, 2),
                )]),
            ),
        );
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Tcp,
            [10, 0, 0, 2],
            [10, 255, 255, 2],
            53000,
            53,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::DnsCapture);
        assert_eq!(outcome.transport, "tcp");
        assert!(outcome
            .reason
            .as_deref()
            .expect("reason")
            .contains("virtual DNS target"));
    }

    #[test]
    fn udp_port_hijack_does_not_capture_tcp_dns_target() {
        let runtime =
            NativeCoreRuntime::compile(&proxy_profile("Proxy", ProxyProtocol::Http, json!({})));
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Tcp,
            [10, 0, 0, 2],
            [198, 18, 0, 1],
            53000,
            53,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        // The UDP-scoped hijack must not answer TCP DNS — and a fake-range
        // target no mapping ever covered is refused instead of relayed.
        assert_ne!(outcome.action, PacketCoreAction::DnsCapture);
        assert_eq!(outcome.action, PacketCoreAction::Reject);
    }

    #[test]
    fn routes_fake_ip_packet_by_original_domain() {
        let mut profile = proxy_profile("Proxy", ProxyProtocol::Http, json!({}));
        profile.rules = vec![
            RouteRule {
                kind: RuleKind::Domain,
                payload: Some("example.com"),
                outbound: "Proxy",
                no_resolve: false,
            },
            RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: "DIRECT",
                no_resolve: false,
            },
        ]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        let fake_ip = runtime
            .fake_dns()
            .allocate_ipv4("example.com")
            .expect("fake IP allocates");
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Tcp,
            [10, 0, 0, 2],
            fake_ip.octets(),
            49152,
            443,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::ProxyTcp);
        assert_eq!(outcome.outbound, "Proxy");
        assert_eq!(outcome.destination_ip, fake_ip.to_string());
        assert_eq!(outcome.destination_host.as_deref(), Some("example.com"));
    }

    #[test]
    fn routes_fake_ipv6_packet_by_original_domain() {
        let mut profile = proxy_profile("Proxy", ProxyProtocol::Http, json!({}));
        profile.rules = vec![
            RouteRule {
                kind: RuleKind::Domain,
                payload: Some("example.com"),
                outbound: "Proxy",
                no_resolve: false,
            },
            RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: "DIRECT",
                no_resolve: false,
            },
        ]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        let fake_ip = runtime
            .fake_dns()
            .allocate_ipv6("example.com")
            .expect("fake IPv6 allocates");
        let mut payload = vec![0_u8; 44];
        payload[0] = 0x60;
        payload[4..6].copy_from_slice(&(4_u16).to_be_bytes());
        payload[6] = 6;
        payload[7] = 64;
        payload[8..24]
            .copy_from_slice(&std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        payload[24..40].copy_from_slice(&fake_ip.octets());
        payload[40..42].copy_from_slice(&49152_u16.to_be_bytes());
        payload[42..44].copy_from_slice(&443_u16.to_be_bytes());

        let outcome = process_captured_packet(&runtime, &CapturedPacket::from_bytes(payload))
            .expect("packet is routed");

        assert_eq!(outcome.action, PacketCoreAction::ProxyTcp);
        assert_eq!(outcome.outbound, "Proxy");
        assert_eq!(outcome.destination_ip, fake_ip.to_string());
        assert_eq!(outcome.destination_host.as_deref(), Some("example.com"));
    }

    fn proxy_profile(
        name: &str,
        protocol: ProxyProtocol,
        options: serde_json::Value,
    ) -> RuntimeProfile {
        RuntimeProfile {
            dns: crate::dns::config::RuntimeDnsConfig {
                enabled: true,
                enhanced_mode: crate::dns::config::DnsMode::FakeIp,
                ..Default::default()
            },
            rule_sets: Vec::new(),
            geodata: Default::default(),
            id: "packet-profile".into(),
            name: "packet-profile".into(),
            traffic_policy_mode: crate::profile::TrafficPolicyMode::Rule,
            global_outbound: None,
            proxies: vec![ProxyNode {
                id: format!("proxy-{name}"),
                name: name.into(),
                protocol,
                server: Some("127.0.0.1".into()),
                port: Some(18080),
                options,
            }],
            groups: Vec::new(),
            rules: vec![RouteRule {
                kind: RuleKind::Match,
                payload: None,
                outbound: name,
                no_resolve: false,
            }]
            .into(),
        }
    }

    #[test]
    fn routes_ipv6_tcp_packet_to_proxy_action() {
        let runtime =
            NativeCoreRuntime::compile(&proxy_profile("Proxy", ProxyProtocol::Http, json!({})));
        let mut payload = vec![0_u8; 44];
        payload[0] = 0x60;
        payload[4..6].copy_from_slice(&(4_u16).to_be_bytes());
        payload[6] = 6;
        payload[7] = 64;
        payload[8..24]
            .copy_from_slice(&std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        payload[24..40].copy_from_slice(
            &std::net::Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111).octets(),
        );
        payload[40..42].copy_from_slice(&49152_u16.to_be_bytes());
        payload[42..44].copy_from_slice(&443_u16.to_be_bytes());
        let packet = CapturedPacket::from_bytes(payload);

        let outcome = process_captured_packet(&runtime, &packet).expect("IPv6 packet routes");

        assert_eq!(outcome.action, PacketCoreAction::ProxyTcp);
        assert_eq!(outcome.outbound, "Proxy");
        assert_eq!(outcome.destination_ip, "2606:4700::1111");
        assert_eq!(outcome.destination_port, Some(443));
        assert_eq!(outcome.transport, "tcp");
    }

    #[test]
    fn rejects_stale_fake_range_destination_without_mapping() {
        let mut profile = RuntimeProfile::new("stale-fake");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        // 198.18.5.5 is inside the fake pool but this session never
        // allocated it: the stale-cache shape after a capture restart.
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Tcp,
            [10, 0, 0, 2],
            [198, 18, 5, 5],
            49152,
            443,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is processed");

        assert_eq!(outcome.action, PacketCoreAction::Reject);
        assert!(
            outcome
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("stale fake-IP"),
            "{outcome:?}"
        );
    }

    #[test]
    fn rejects_stale_fake_ipv6_destination_without_mapping() {
        let mut profile = RuntimeProfile::new("stale-fake-v6");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        let mut payload = vec![0_u8; 44];
        payload[0] = 0x60;
        payload[4..6].copy_from_slice(&(4_u16).to_be_bytes());
        payload[6] = 6;
        payload[7] = 64;
        payload[8..24]
            .copy_from_slice(&std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
        payload[24..40].copy_from_slice(
            &std::net::Ipv6Addr::new(0xfd11, 0x5ca1, 0xab1e, 1, 0, 0, 0xc612, 5).octets(),
        );
        payload[40..42].copy_from_slice(&49152_u16.to_be_bytes());
        payload[42..44].copy_from_slice(&443_u16.to_be_bytes());

        let outcome = process_captured_packet(&runtime, &CapturedPacket::from_bytes(payload))
            .expect("packet is processed");

        assert_eq!(outcome.action, PacketCoreAction::Reject);
        assert!(
            outcome
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("stale fake-IP"),
            "{outcome:?}"
        );
    }

    #[test]
    fn stale_fake_rejection_does_not_shadow_dns_capture() {
        let mut profile = RuntimeProfile::new("stale-fake-dns");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        let runtime = NativeCoreRuntime::compile(&profile);
        // A hijacked DNS query aimed at an unmapped fake-range address must
        // still be answered by the engine, not rejected.
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Udp,
            [10, 0, 0, 2],
            [198, 18, 5, 5],
            53000,
            53,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is processed");

        assert_eq!(outcome.action, PacketCoreAction::DnsCapture);
    }

    #[test]
    fn mapped_fake_destination_still_routes_by_domain() {
        let mut profile = RuntimeProfile::new("mapped-fake");
        profile.dns.enabled = true;
        profile.dns.enhanced_mode = crate::dns::config::DnsMode::FakeIp;
        profile.rules = vec![RouteRule {
            kind: RuleKind::Match,
            payload: None,
            outbound: "DIRECT",
            no_resolve: false,
        }]
        .into();
        let runtime = NativeCoreRuntime::compile(&profile);
        let fake_ip = runtime
            .fake_dns()
            .allocate_ipv4("mapped.example")
            .expect("allocate fake IP");
        let packet = CapturedPacket::from_bytes(build_ipv4_packet(
            IpTransportProtocol::Tcp,
            [10, 0, 0, 2],
            fake_ip.octets(),
            49152,
            443,
        ));

        let outcome = process_captured_packet(&runtime, &packet).expect("packet is processed");

        assert_eq!(outcome.action, PacketCoreAction::DirectTcp);
        assert_eq!(outcome.destination_host.as_deref(), Some("mapped.example"));
    }
}
