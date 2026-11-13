//! The leak-protection filter plan: which filters a tunnel's settings ask
//! for, as data, before any of it reaches the filtering engine.

use super::*;

/// The filters that keep what the tunnel captures from leaking around it
/// while it runs, and nothing more: DNS outside the tunnel, IPv6 the tunnel
/// does not carry, and connects to fake IPs outside it. What other software
/// sends outside the tunnel on purpose (another VPN's own connections, a
/// socket bound to an interface) passes. The dynamic session holding them
/// ends with the tunnel, so a stopped or crashed Egrio leaves the network as
/// it is without Egrio.
pub fn windows_firewall_kill_switch_filter_plan(
    input: WindowsFirewallKillSwitchFilterPlanInput,
) -> WindowsFirewallKillSwitchFilterPlan {
    let mut filters = Vec::new();
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    let families = |v6: bool| {
        if v6 {
            vec![
                WindowsFirewallKillSwitchLayer::AleAuthConnectV4,
                WindowsFirewallKillSwitchLayer::AleAuthConnectV6,
            ]
        } else {
            vec![WindowsFirewallKillSwitchLayer::AleAuthConnectV4]
        }
    };
    // The families that enter the tunnel.
    let tunneled = families(input.ipv6.tunnels_v6());

    if input.protected_app_paths.is_empty() {
        blockers.push(
            "Windows leak protection requires at least one protected Egrio executable path".into(),
        );
    }
    // Egrio resolves the names of its nodes and DNS servers through the
    // uplink's resolvers itself.
    for app_path in normalized_app_paths(&input.protected_app_paths) {
        for layer in &tunneled {
            filters.push(WindowsFirewallKillSwitchFilterSpec {
                key: format!(
                    "permit-dns-app-{}-{}",
                    layer.key_suffix(),
                    stable_key_fragment(&app_path)
                ),
                name: format!("Permit Egrio app DNS egress on {}", layer.display_name()),
                role: WindowsFirewallKillSwitchFilterRole::PermitDnsEgress,
                sublayer: WindowsFirewallSublayerKind::DnsLeakPrevention,
                layer: layer.clone(),
                action: WindowsFirewallKillSwitchAction::Permit,
                weight: 30_000,
                conditions: vec![
                    WindowsFirewallKillSwitchCondition {
                        field: WindowsFirewallKillSwitchConditionField::AleAppId,
                        matcher: "equals-app-id-from-path".into(),
                        value: app_path.clone(),
                    },
                    WindowsFirewallKillSwitchCondition {
                        field: WindowsFirewallKillSwitchConditionField::IpRemotePort,
                        matcher: "equals".into(),
                        value: "53".into(),
                    },
                ],
                rationale: "Egrio resolves its nodes and DNS servers through the uplink's resolvers"
                    .into(),
            });
        }
    }

    match input.wintun_interface_index {
        Some(interface_index) => {
            for layer in &tunneled {
                filters.push(WindowsFirewallKillSwitchFilterSpec {
                    key: format!(
                        "permit-wintun-if-{}-{}",
                        layer.key_suffix(),
                        interface_index
                    ),
                    name: format!(
                        "Permit Wintun interface traffic on {}",
                        layer.display_name()
                    ),
                    role: WindowsFirewallKillSwitchFilterRole::PermitWintunInterface,
                    sublayer: WindowsFirewallSublayerKind::Traffic,
                    layer: layer.clone(),
                    action: WindowsFirewallKillSwitchAction::Permit,
                    weight: 20_000,
                    conditions: vec![WindowsFirewallKillSwitchCondition {
                        field: WindowsFirewallKillSwitchConditionField::InterfaceIndex,
                        matcher: "equals".into(),
                        value: interface_index.to_string(),
                    }],
                    rationale:
                        "Traffic routed into the Wintun adapter reaches the Core, fake IPs included"
                            .into(),
                });
            }
        }
        None => blockers
            .push("Windows leak protection requires the Wintun adapter interface index".into()),
    }

    // A fake IP means something only to the Core. A socket that bypasses the
    // tunnel (bound to the physical interface) gets one from the system
    // resolver like every other; blocked, its connect fails at once and a
    // client with an independent DNS bootstrap can recover, where it
    // would otherwise wait for a peer that is not
    // there. The Wintun permit above lets the tunnel's own traffic to them by.
    for prefix in &input.fake_ip_prefixes {
        let layer = layer_of(prefix.address);
        if !tunneled.contains(&layer) {
            continue;
        }
        filters.push(WindowsFirewallKillSwitchFilterSpec {
            key: format!(
                "block-fake-ip-{}-{}",
                stable_key_fragment(&prefix.to_string()),
                layer.key_suffix()
            ),
            name: format!(
                "Block fake IPs {prefix} outside the tunnel on {}",
                layer.display_name()
            ),
            role: WindowsFirewallKillSwitchFilterRole::BlockFakeIp,
            sublayer: WindowsFirewallSublayerKind::Traffic,
            layer,
            action: WindowsFirewallKillSwitchAction::Block,
            weight: 12_000,
            conditions: vec![WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::IpRemoteAddress,
                matcher: "equals".into(),
                value: prefix.to_string(),
            }],
            rationale: "Outside the tunnel a fake IP reaches nothing; the connect fails at once"
                .into(),
        });
    }

    // IPv6 the tunnel does not carry would leave by the physical network:
    // blocked, but for loopback, the link-local and multicast scopes (DHCPv6,
    // router advertisements, LAN discovery) and excluded destinations.
    if input.ipv6.blocks_v6() {
        let layer = WindowsFirewallKillSwitchLayer::AleAuthConnectV6;
        let mut permit =
            |key: String, name: String, role, weight, value: String, rationale: &str| {
                filters.push(WindowsFirewallKillSwitchFilterSpec {
                    key,
                    name,
                    role,
                    sublayer: WindowsFirewallSublayerKind::Traffic,
                    layer: layer.clone(),
                    action: WindowsFirewallKillSwitchAction::Permit,
                    weight,
                    conditions: vec![WindowsFirewallKillSwitchCondition {
                        field: WindowsFirewallKillSwitchConditionField::IpRemoteAddress,
                        matcher: "equals".into(),
                        value,
                    }],
                    rationale: rationale.into(),
                })
            };
        permit(
            "permit-loopback-ale-auth-connect-v6".into(),
            "Permit IPv6 loopback traffic on ALE_AUTH_CONNECT_V6".into(),
            WindowsFirewallKillSwitchFilterRole::PermitLoopback,
            25_000,
            "::1/128".into(),
            "IPv6 loopback stays on the host",
        );
        for (fragment, value) in [("link-local", "fe80::/10"), ("multicast", "ff00::/8")] {
            permit(
                format!("permit-lan-{fragment}-ale-auth-connect-v6"),
                format!("Permit LAN {value} on ALE_AUTH_CONNECT_V6"),
                WindowsFirewallKillSwitchFilterRole::PermitLanBypass,
                15_000,
                value.into(),
                "Link-local and multicast IPv6 cannot route to the internet",
            );
        }
        for prefix in input
            .excluded_prefixes
            .iter()
            .filter(|prefix| prefix.address.is_ipv6())
        {
            permit(
                format!(
                    "permit-excluded-{}-ale-auth-connect-v6",
                    stable_key_fragment(&prefix.to_string())
                ),
                format!("Permit excluded destination {prefix} on ALE_AUTH_CONNECT_V6"),
                WindowsFirewallKillSwitchFilterRole::PermitExcludedDestination,
                15_000,
                prefix.to_string(),
                "Excluded destinations are routed outside the tunnel on purpose",
            );
        }
        filters.push(WindowsFirewallKillSwitchFilterSpec {
            key: "block-ipv6-ale-auth-connect-v6".into(),
            name: "Block IPv6 the tunnel does not carry on ALE_AUTH_CONNECT_V6".into(),
            role: WindowsFirewallKillSwitchFilterRole::BlockUntunneledIpv6,
            sublayer: WindowsFirewallSublayerKind::Traffic,
            layer,
            action: WindowsFirewallKillSwitchAction::Block,
            weight: 1_000,
            conditions: Vec::new(),
            rationale: "No IPv6 enters the tunnel, so none may leave by the physical network"
                .into(),
        });
    }

    // Windows' resolver asks every interface's DNS servers at once; without
    // this block each query also leaves by the physical network, and an
    // answer from there would bypass the fake IPs. DNS to excluded
    // destinations and LAN resolvers is blocked too. Only the physical
    // uplinks: DNS another VPN sends into its own adapter goes to that VPN's
    // resolver. Consecutive conditions on one field are ORed (FWPM_FILTER0).
    for layer in families(input.ipv6.guards_v6_dns()) {
        let mut conditions = vec![WindowsFirewallKillSwitchCondition {
            field: WindowsFirewallKillSwitchConditionField::IpRemotePort,
            matcher: "equals".into(),
            value: "53".into(),
        }];
        conditions.extend(UPLINK_INTERFACE_TYPES.iter().map(|interface_type| {
            WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::InterfaceType,
                matcher: "equals".into(),
                value: interface_type.to_string(),
            }
        }));
        filters.push(WindowsFirewallKillSwitchFilterSpec {
            key: format!("block-dns-leak-{}", layer.key_suffix()),
            name: format!("Block DNS leaks on {}", layer.display_name()),
            role: WindowsFirewallKillSwitchFilterRole::BlockDnsLeak,
            sublayer: WindowsFirewallSublayerKind::DnsLeakPrevention,
            layer,
            action: WindowsFirewallKillSwitchAction::Block,
            weight: 1_000,
            conditions,
            rationale: "DNS to remote port 53 by a physical uplink goes through the tunnel or is Egrio's own".into(),
        });
    }

    warnings.push(match input.ipv6 {
        WindowsFirewallIpv6Mode::Tunnel => "IPv6 is tunneled like IPv4".into(),
        WindowsFirewallIpv6Mode::Block => {
            "IPv6 is blocked: global IPv6 does not enter the tunnel and does not leak while capture is active".into()
        }
        WindowsFirewallIpv6Mode::Off => {
            "IPv6 filters are disabled: global IPv6 is left to the OS and can leak past the captured IPv4 default route".into()
        }
    });

    WindowsFirewallKillSwitchFilterPlan {
        production_ready: blockers.is_empty(),
        filters,
        blockers,
        warnings,
    }
}

impl WindowsFirewallKillSwitchLayer {
    pub(super) fn key_suffix(&self) -> &'static str {
        match self {
            WindowsFirewallKillSwitchLayer::AleAuthConnectV4 => "ale-auth-connect-v4",
            WindowsFirewallKillSwitchLayer::AleAuthConnectV6 => "ale-auth-connect-v6",
        }
    }

    pub(super) fn display_name(&self) -> &'static str {
        match self {
            WindowsFirewallKillSwitchLayer::AleAuthConnectV4 => "ALE_AUTH_CONNECT_V4",
            WindowsFirewallKillSwitchLayer::AleAuthConnectV6 => "ALE_AUTH_CONNECT_V6",
        }
    }

    pub(super) fn supports_condition_field(
        &self,
        field: &WindowsFirewallKillSwitchConditionField,
    ) -> bool {
        match field {
            WindowsFirewallKillSwitchConditionField::AleAppId => matches!(
                self,
                WindowsFirewallKillSwitchLayer::AleAuthConnectV4
                    | WindowsFirewallKillSwitchLayer::AleAuthConnectV6
            ),
            WindowsFirewallKillSwitchConditionField::InterfaceIndex => matches!(
                self,
                WindowsFirewallKillSwitchLayer::AleAuthConnectV4
                    | WindowsFirewallKillSwitchLayer::AleAuthConnectV6
            ),
            // FWPM_CONDITION_INTERFACE_TYPE is a documented filtering condition
            // at the ALE_AUTH_CONNECT layers ("Filtering conditions available
            // at each filtering layer", Fwpmu.h).
            WindowsFirewallKillSwitchConditionField::InterfaceType => matches!(
                self,
                WindowsFirewallKillSwitchLayer::AleAuthConnectV4
                    | WindowsFirewallKillSwitchLayer::AleAuthConnectV6
            ),
            // FWPM_CONDITION_IP_PROTOCOL is a documented filtering condition
            // at the ALE_AUTH_CONNECT layers ("Filtering conditions available
            // at each filtering layer", Fwpmu.h).
            WindowsFirewallKillSwitchConditionField::IpProtocol => matches!(
                self,
                WindowsFirewallKillSwitchLayer::AleAuthConnectV4
                    | WindowsFirewallKillSwitchLayer::AleAuthConnectV6
            ),
            WindowsFirewallKillSwitchConditionField::IpLocalAddress => false,
            // FWPM_CONDITION_IP_REMOTE_ADDRESS is a documented filtering
            // condition at the ALE_AUTH_CONNECT layers (WFP layer condition
            // matrix), which the fake-IP blocks and IPv6 permits rely on.
            WindowsFirewallKillSwitchConditionField::IpRemoteAddress => matches!(
                self,
                WindowsFirewallKillSwitchLayer::AleAuthConnectV4
                    | WindowsFirewallKillSwitchLayer::AleAuthConnectV6
            ),
            WindowsFirewallKillSwitchConditionField::IpRemotePort => matches!(
                self,
                WindowsFirewallKillSwitchLayer::AleAuthConnectV4
                    | WindowsFirewallKillSwitchLayer::AleAuthConnectV6
            ),
        }
    }
}

fn normalized_app_paths(app_paths: &[String]) -> Vec<String> {
    let mut app_paths = app_paths
        .iter()
        .map(|path| path.trim())
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    app_paths.sort();
    app_paths.dedup();
    app_paths
}

fn stable_key_fragment(value: &str) -> String {
    let mut fragment = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    while fragment.contains("--") {
        fragment = fragment.replace("--", "-");
    }
    fragment.trim_matches('-').to_string()
}
