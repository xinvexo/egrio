//! Leak protection through the Windows Filtering Platform, with no driver of
//! Egrio's own: a dynamic session's provider, sublayers and filters, which
//! the Base Filtering Engine releases with the session. This file holds the
//! provider's keys and the sublayers' profile; its parts hold the rest:
//!
//! - `plan` — the filters a tunnel's settings ask for, as data;
//! - `conditions` — a filter's conditions as the engine takes them;
//! - `engine` — the open engine: adding, and enumerating what is Egrio's;
//! - `session` — the session that holds a plan's filters while its tunnel
//!   carries packets;
//! - `net_events` — the read-only diagnostic of dropped connections.

use std::collections::BTreeSet;
use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

use windows_sys::core::{GUID, PWSTR};
use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, FILETIME, FWP_E_ALREADY_EXISTS, FWP_E_NET_EVENTS_DISABLED, HANDLE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211, IF_TYPE_IEEE80216_WMAN, IF_TYPE_PPP,
    IF_TYPE_WWANPP, IF_TYPE_WWANPP2,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0,
    FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmNetEventCreateEnumHandle0, FwpmNetEventDestroyEnumHandle0,
    FwpmNetEventEnum5, FwpmProviderAdd0, FwpmSubLayerAdd0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID,
    FWPM_CONDITION_INTERFACE_INDEX, FWPM_CONDITION_INTERFACE_TYPE, FWPM_CONDITION_IP_LOCAL_ADDRESS,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_NET_EVENT5, FWPM_NET_EVENT_ENUM_TEMPLATE0,
    FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET, FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
    FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
    FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET, FWPM_NET_EVENT_FLAG_SCOPE_ID_SET, FWPM_NET_EVENT_TYPE,
    FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW, FWPM_NET_EVENT_TYPE_CAPABILITY_DROP,
    FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW, FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
    FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC, FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE,
    FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE, FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE,
    FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP, FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP,
    FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL, FWPM_PROVIDER0, FWPM_SESSION0,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SUBLAYER0, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_IP_VERSION,
    FWP_IP_VERSION_NONE, FWP_IP_VERSION_V4, FWP_IP_VERSION_V6, FWP_MATCH_EQUAL, FWP_UINT16,
    FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use serde::{Deserialize, Serialize};

use super::{
    WindowsFirewallIpv6Mode, WindowsFirewallKillSwitchAction, WindowsFirewallKillSwitchCondition,
    WindowsFirewallKillSwitchConditionField, WindowsFirewallKillSwitchFilterPlan,
    WindowsFirewallKillSwitchFilterPlanInput, WindowsFirewallKillSwitchFilterRole,
    WindowsFirewallKillSwitchFilterSpec, WindowsFirewallKillSwitchLayer,
    WindowsFirewallNetEventDiagnosticInput, WindowsFirewallNetEventDiagnosticReport,
    WindowsFirewallNetEventLayerSummary, WindowsFirewallNetEventRecord,
    WindowsFirewallSublayerKind,
};

mod conditions;
mod engine;
mod net_events;
mod plan;
mod session;

use conditions::*;
use engine::*;
pub use net_events::*;
pub use plan::*;
pub use session::*;

const EGRIO_WFP_PROVIDER_KEY: GUID = GUID::from_u128(0x2d606d68_04e0_4562_aa73_01fabf004a40);
const EGRIO_WFP_SUBLAYER_KEY: GUID = GUID::from_u128(0x58c4a8e7_4982_4d63_86a6_6b218f467907);
const EGRIO_WFP_SUBLAYER_WEIGHT: u16 = 0x7000;
const EGRIO_WFP_DNS_SUBLAYER_KEY: GUID = GUID::from_u128(0x3c5ee724_8b01_4f2e_8f4c_9cd316bc1d03);
const EGRIO_WFP_DNS_SUBLAYER_WEIGHT: u16 = 0x7200;
const FWPS_LAYER_OUTBOUND_TRANSPORT_V4_ID: u16 = 16;
const FWPS_LAYER_OUTBOUND_TRANSPORT_V6_ID: u16 = 18;
const FWPS_LAYER_ALE_AUTH_CONNECT_V4_ID: u16 = 48;
const FWPS_LAYER_ALE_AUTH_CONNECT_V6_ID: u16 = 50;
/// The interface types of physical uplinks (`MIB_IF_ROW2.Type`, Ipifcons.h):
/// Ethernet, PPP, Wi-Fi and mobile broadband (the link types, not a mobile
/// platform). Wintun adapters, Egrio's and
/// other VPNs', are none of them.
const UPLINK_INTERFACE_TYPES: [u32; 6] = [
    IF_TYPE_ETHERNET_CSMACD,
    IF_TYPE_PPP,
    IF_TYPE_IEEE80211,
    IF_TYPE_IEEE80216_WMAN,
    IF_TYPE_WWANPP,
    IF_TYPE_WWANPP2,
];

#[derive(Clone, Copy)]
struct WfpSessionProfile {
    provider_key: GUID,
    provider_name: &'static str,
    provider_description: &'static str,
    sublayers: &'static [WfpSublayerProfile],
    session_description: &'static str,
    active_warning: &'static str,
}

#[derive(Clone, Copy)]
struct WfpSublayerProfile {
    kind: WindowsFirewallSublayerKind,
    key: GUID,
    weight: u16,
    name: &'static str,
    description: &'static str,
}

const EGRIO_WFP_KILL_SWITCH_SUBLAYERS: [WfpSublayerProfile; 2] = [
    WfpSublayerProfile {
        kind: WindowsFirewallSublayerKind::Traffic,
        key: EGRIO_WFP_SUBLAYER_KEY,
        weight: EGRIO_WFP_SUBLAYER_WEIGHT,
        name: "Egrio TUN leak protection",
        description: "Egrio-owned WFP sublayer for Windows TUN leak-protection rules",
    },
    WfpSublayerProfile {
        kind: WindowsFirewallSublayerKind::DnsLeakPrevention,
        key: EGRIO_WFP_DNS_SUBLAYER_KEY,
        weight: EGRIO_WFP_DNS_SUBLAYER_WEIGHT,
        name: "Egrio DNS leak prevention",
        description:
            "Egrio-owned WFP sublayer for ALE remote-port 53 DNS permit-list and block rules",
    },
];

const EGRIO_WFP_KILL_SWITCH_PROFILE: WfpSessionProfile = WfpSessionProfile {
    provider_key: EGRIO_WFP_PROVIDER_KEY,
    provider_name: "Egrio",
    provider_description: "Egrio Windows TUN leak-prevention provider",
    sublayers: &EGRIO_WFP_KILL_SWITCH_SUBLAYERS,
    session_description: "Egrio owns this dynamic WFP session while Windows TUN mode is active",
    active_warning: "WFP provider/sublayer session is active; leak-protection filters are session-scoped and released by BFE when the dynamic session closes",
};

impl WfpSessionProfile {
    fn sublayer_key_for(&self, kind: WindowsFirewallSublayerKind) -> Result<GUID, String> {
        self.sublayers
            .iter()
            .find(|sublayer| sublayer.kind == kind)
            .map(|sublayer| sublayer.key)
            .ok_or_else(|| {
                format!(
                    "WFP profile '{}' does not register a {:?} sublayer",
                    self.provider_name, kind
                )
            })
    }
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

fn display_data(name: &mut [u16], description: &mut [u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: name.as_mut_ptr() as PWSTR,
        description: description.as_mut_ptr() as PWSTR,
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn ensure_wfp_add_ok(status: u32, operation: &str) -> Result<bool, String> {
    if status == ERROR_SUCCESS {
        Ok(true)
    } else if status == FWP_E_ALREADY_EXISTS as u32 {
        Ok(false)
    } else {
        Err(format!("{operation} failed with WFP status 0x{status:08x}"))
    }
}

fn ensure_wfp_ok(status: u32, operation: &str) -> Result<(), String> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(wfp_status_error(operation, status))
    }
}

fn wfp_status_error(operation: &str, status: u32) -> String {
    format!("{operation} failed with WFP status 0x{status:08x}")
}

fn guid_string(guid: GUID) -> String {
    let data4 = guid.data4;
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egrio_wfp_keys_are_stable() {
        assert_eq!(
            guid_string(EGRIO_WFP_PROVIDER_KEY),
            "2d606d68-04e0-4562-aa73-01fabf004a40"
        );
        assert_eq!(
            guid_string(EGRIO_WFP_SUBLAYER_KEY),
            "58c4a8e7-4982-4d63-86a6-6b218f467907"
        );
    }

    #[test]
    fn wide_null_terminates_without_losing_text() {
        let encoded = wide_null("Egrio");

        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(
            String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
            "Egrio"
        );
    }

    #[test]
    fn net_event_type_names_are_stable() {
        assert_eq!(
            net_event_type_name(FWPM_NET_EVENT_TYPE_CLASSIFY_DROP),
            "classify-drop"
        );
        assert_eq!(
            net_event_type_name(FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW),
            "classify-allow"
        );
        assert_eq!(net_event_type_name(9_999), "unknown");
    }

    #[test]
    fn net_event_ipv4_addresses_are_reported_with_raw_value() {
        let (addr, raw) = net_event_addr(
            FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
            FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
            FWP_IP_VERSION_V4,
            || 0x0aff_ff02,
            || [0; 16],
        );

        assert_eq!(addr.as_deref(), Some("10.255.255.2"));
        assert_eq!(raw.as_deref(), Some("0x0affff02"));
    }

    #[test]
    fn net_event_layer_names_follow_sdk_builtin_ids() {
        assert_eq!(
            net_event_fwps_layer_name(FWPS_LAYER_OUTBOUND_TRANSPORT_V4_ID),
            Some("FWPS_LAYER_OUTBOUND_TRANSPORT_V4")
        );
        assert_eq!(
            net_event_fwps_layer_name(FWPS_LAYER_ALE_AUTH_CONNECT_V4_ID),
            Some("FWPS_LAYER_ALE_AUTH_CONNECT_V4")
        );
        assert_eq!(net_event_fwps_layer_name(999), None);
    }

    #[test]
    fn net_event_dns_relevant_layers_group_by_fwps_layer() {
        let events = vec![
            test_net_event_record(
                Some(FWPS_LAYER_ALE_AUTH_CONNECT_V4_ID),
                Some("FWPS_LAYER_ALE_AUTH_CONNECT_V4"),
                true,
            ),
            test_net_event_record(
                Some(FWPS_LAYER_ALE_AUTH_CONNECT_V4_ID),
                Some("FWPS_LAYER_ALE_AUTH_CONNECT_V4"),
                true,
            ),
            test_net_event_record(
                Some(FWPS_LAYER_OUTBOUND_TRANSPORT_V4_ID),
                Some("FWPS_LAYER_OUTBOUND_TRANSPORT_V4"),
                true,
            ),
            test_net_event_record(None, None, false),
        ];

        let summaries = net_event_dns_relevant_layers(&events);

        assert_eq!(summaries.len(), 2);
        assert_eq!(
            summaries[0].layer_id,
            Some(FWPS_LAYER_OUTBOUND_TRANSPORT_V4_ID)
        );
        assert_eq!(summaries[0].dns_relevant_events, 1);
        assert_eq!(
            summaries[1].layer_id,
            Some(FWPS_LAYER_ALE_AUTH_CONNECT_V4_ID)
        );
        assert_eq!(summaries[1].dns_relevant_events, 2);
    }

    #[test]
    fn net_event_diagnostic_rejects_reversed_time_window_before_opening_engine() {
        let report = windows_firewall_net_event_diagnostic_with_input(
            WindowsFirewallNetEventDiagnosticInput {
                events_requested: 64,
                event_window_start_filetime: Some(200),
                event_window_end_filetime: Some(100),
                enum_filter_conditions: Vec::new(),
            },
        );

        assert!(!report.engine_opened);
        assert_eq!(report.event_window_start_filetime, Some(200));
        assert_eq!(report.event_window_end_filetime, Some(100));
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("start 200 is after end 100")));
    }

    #[test]
    fn net_event_template_condition_support_is_explicit() {
        assert!(net_event_enum_condition_field_supported(
            &WindowsFirewallKillSwitchConditionField::IpRemotePort
        ));
        assert!(net_event_enum_condition_field_supported(
            &WindowsFirewallKillSwitchConditionField::IpProtocol
        ));
        assert!(!net_event_enum_condition_field_supported(
            &WindowsFirewallKillSwitchConditionField::InterfaceIndex
        ));
    }

    #[test]
    fn filetime_u64_conversion_round_trips() {
        let filetime = filetime_from_u64(0x0123_4567_89ab_cdef);

        assert_eq!(filetime_to_u64(filetime), 0x0123_4567_89ab_cdef);
    }

    #[test]
    fn net_event_dns_relevance_requires_dns_port() {
        assert!(net_event_is_dns_relevant(Some(12345), Some(53), Some(17)));
        assert!(net_event_is_dns_relevant(Some(53), Some(12345), Some(17)));
        assert!(!net_event_is_dns_relevant(Some(12345), Some(443), Some(17)));
    }

    fn plan_for(
        ipv6: WindowsFirewallIpv6Mode,
        excluded_prefixes: &[&str],
    ) -> WindowsFirewallKillSwitchFilterPlan {
        plan_protecting(r"C:\Program Files\Egrio\egrio.exe", ipv6, excluded_prefixes)
    }

    fn plan_protecting(
        app: &str,
        ipv6: WindowsFirewallIpv6Mode,
        excluded_prefixes: &[&str],
    ) -> WindowsFirewallKillSwitchFilterPlan {
        windows_firewall_kill_switch_filter_plan(WindowsFirewallKillSwitchFilterPlanInput {
            wintun_interface_index: Some(42),
            protected_app_paths: vec![app.into(), app.into()],
            ipv6,
            excluded_prefixes: excluded_prefixes
                .iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect(),
            fake_ip_prefixes: vec![
                "198.18.0.0/16".parse().unwrap(),
                "fd11:5ca1:ab1e:1::c612:0/112".parse().unwrap(),
            ],
        })
    }

    fn keys(plan: &WindowsFirewallKillSwitchFilterPlan) -> Vec<&str> {
        let mut keys = plan
            .filters
            .iter()
            .map(|filter| filter.key.as_str())
            .collect::<Vec<_>>();
        keys.sort();
        keys
    }

    /// Only leaks are blocked: DNS outside the tunnel and fake IPs outside
    /// it. Nothing else of IPv4 is, so what other software sends outside the
    /// tunnel on purpose passes, and no permit is needed to let it.
    #[test]
    fn a_tunneled_plan_blocks_only_dns_and_fake_ips_outside_the_tunnel() {
        let plan = plan_for(WindowsFirewallIpv6Mode::Tunnel, &["100.64.0.0/10"]);
        assert!(plan.production_ready);
        assert_eq!(
            keys(&plan),
            [
                "block-dns-leak-ale-auth-connect-v4",
                "block-dns-leak-ale-auth-connect-v6",
                "block-fake-ip-198-18-0-0-16-ale-auth-connect-v4",
                "block-fake-ip-fd11-5ca1-ab1e-1-c612-0-112-ale-auth-connect-v6",
                "permit-dns-app-ale-auth-connect-v4-c-program-files-egrio-egrio-exe",
                "permit-dns-app-ale-auth-connect-v6-c-program-files-egrio-egrio-exe",
                "permit-wintun-if-ale-auth-connect-v4-42",
                "permit-wintun-if-ale-auth-connect-v6-42",
            ]
        );
        // The app's permit names a program by the identifier WFP derives from
        // its file, which has to exist for that: the running test stands in
        // for an installed Egrio, which a machine running this may not have.
        let this_program = std::env::current_exe().unwrap();
        let mapped = plan_protecting(
            this_program.to_str().unwrap(),
            WindowsFirewallIpv6Mode::Tunnel,
            &["100.64.0.0/10"],
        );
        assert_eq!(mapped.filters.len(), plan.filters.len());
        for filter in &mapped.filters {
            validate_filter_spec_conditions(filter).expect("conditions valid on ALE_AUTH_CONNECT");
            let mut resources = FilterConditionResources::default();
            for condition in &filter.conditions {
                build_wfp_condition(condition, &mut resources).expect("condition maps to WFP");
            }
            if filter.action == WindowsFirewallKillSwitchAction::Block {
                assert!(
                    !filter.conditions.is_empty(),
                    "{} blocks only a leak",
                    filter.key
                );
            }
        }
        // The tunnel's own traffic to fake IPs outweighs their block.
        let weight = |role| {
            plan.filters
                .iter()
                .find(|filter| filter.role == role)
                .unwrap()
                .weight
        };
        assert!(
            weight(WindowsFirewallKillSwitchFilterRole::PermitWintunInterface)
                > weight(WindowsFirewallKillSwitchFilterRole::BlockFakeIp)
        );
        let dns = plan
            .filters
            .iter()
            .find(|filter| filter.key == "block-dns-leak-ale-auth-connect-v4")
            .unwrap();
        assert_eq!(dns.sublayer, WindowsFirewallSublayerKind::DnsLeakPrevention);
        assert_eq!(
            dns.conditions[0].field,
            WindowsFirewallKillSwitchConditionField::IpRemotePort
        );
        assert_eq!(dns.conditions[0].value, "53");
        // DNS leaving by a physical uplink only: another VPN's into its own
        // adapter passes. The interface types follow one another, so WFP ORs
        // them.
        let types: Vec<&str> = dns.conditions[1..]
            .iter()
            .map(|condition| {
                assert_eq!(
                    condition.field,
                    WindowsFirewallKillSwitchConditionField::InterfaceType
                );
                condition.value.as_str()
            })
            .collect();
        assert_eq!(types, ["6", "23", "71", "237", "243", "244"]);
    }

    #[test]
    fn interface_type_condition_maps_to_wfp_uint32() {
        let mut resources = FilterConditionResources::default();
        let condition = build_wfp_condition(
            &WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::InterfaceType,
                matcher: "equals".into(),
                value: "71".into(),
            },
            &mut resources,
        )
        .expect("interface type condition");

        assert_eq!(
            guid_string(condition.fieldKey),
            guid_string(FWPM_CONDITION_INTERFACE_TYPE)
        );
        assert_eq!(condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.conditionValue.r#type, FWP_UINT32);
        assert_eq!(unsafe { condition.conditionValue.Anonymous.uint32 }, 71);
    }

    /// IPv6 the tunnel does not carry is blocked but for loopback, the LAN
    /// scopes and excluded destinations; with `Off` nothing of IPv6 is.
    #[test]
    fn ipv6_is_tunneled_blocked_or_left_alone() {
        let block = plan_for(
            WindowsFirewallIpv6Mode::Block,
            &["100.64.0.0/10", "fd7a:115c:a1e0::/48"],
        );
        fn v6(plan: &WindowsFirewallKillSwitchFilterPlan) -> Vec<&str> {
            plan.filters
                .iter()
                .filter(|filter| filter.layer == WindowsFirewallKillSwitchLayer::AleAuthConnectV6)
                .map(|filter| filter.key.as_str())
                .collect()
        }
        assert_eq!(
            v6(&block),
            [
                "permit-loopback-ale-auth-connect-v6",
                "permit-lan-link-local-ale-auth-connect-v6",
                "permit-lan-multicast-ale-auth-connect-v6",
                "permit-excluded-fd7a-115c-a1e0-48-ale-auth-connect-v6",
                "block-ipv6-ale-auth-connect-v6",
                "block-dns-leak-ale-auth-connect-v6",
            ]
        );
        let ipv6_block = block
            .filters
            .iter()
            .find(|filter| filter.role == WindowsFirewallKillSwitchFilterRole::BlockUntunneledIpv6)
            .unwrap();
        assert!(ipv6_block.conditions.is_empty());
        assert!(block
            .filters
            .iter()
            .filter(
                |filter| filter.layer == WindowsFirewallKillSwitchLayer::AleAuthConnectV6
                    && filter.action == WindowsFirewallKillSwitchAction::Permit
            )
            .all(|filter| filter.weight > ipv6_block.weight));
        assert!(block
            .warnings
            .iter()
            .any(|warning| warning.contains("IPv6 is blocked")));

        assert!(v6(&plan_for(WindowsFirewallIpv6Mode::Off, &[])).is_empty());
        let tunnel = plan_for(WindowsFirewallIpv6Mode::Tunnel, &["fd7a:115c:a1e0::/48"]);
        assert!(!tunnel.filters.iter().any(|filter| matches!(
            filter.role,
            WindowsFirewallKillSwitchFilterRole::BlockUntunneledIpv6
                | WindowsFirewallKillSwitchFilterRole::PermitExcludedDestination
        )));
    }

    #[test]
    fn filter_plan_blocks_without_app_paths_or_wintun_index() {
        let plan =
            windows_firewall_kill_switch_filter_plan(WindowsFirewallKillSwitchFilterPlanInput {
                wintun_interface_index: None,
                protected_app_paths: Vec::new(),
                ipv6: WindowsFirewallIpv6Mode::Off,
                excluded_prefixes: Vec::new(),
                fake_ip_prefixes: Vec::new(),
            });

        assert!(!plan.production_ready);
        assert!(plan
            .blockers
            .iter()
            .any(|blocker| blocker.contains("executable path")));
        assert!(plan
            .blockers
            .iter()
            .any(|blocker| blocker.contains("interface index")));
        assert!(plan.warnings.iter().any(|warning| warning.contains("IPv6")));
    }

    #[test]
    fn wfp_layer_and_action_mappings_are_stable() {
        assert_eq!(
            guid_string(layer_key(&WindowsFirewallKillSwitchLayer::AleAuthConnectV4)),
            guid_string(FWPM_LAYER_ALE_AUTH_CONNECT_V4)
        );
        assert_eq!(
            action_type(&WindowsFirewallKillSwitchAction::Permit),
            FWP_ACTION_PERMIT
        );
        assert_eq!(
            action_type(&WindowsFirewallKillSwitchAction::Block),
            FWP_ACTION_BLOCK
        );
    }

    #[test]
    fn interface_index_condition_maps_to_wfp_uint32() {
        let mut resources = FilterConditionResources::default();
        let condition = build_wfp_condition(
            &WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::InterfaceIndex,
                matcher: "equals".into(),
                value: "42".into(),
            },
            &mut resources,
        )
        .expect("interface index condition");

        assert_eq!(
            guid_string(condition.fieldKey),
            guid_string(FWPM_CONDITION_INTERFACE_INDEX)
        );
        assert_eq!(condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.conditionValue.r#type, FWP_UINT32);
        assert_eq!(unsafe { condition.conditionValue.Anonymous.uint32 }, 42);
    }

    #[test]
    fn ip_protocol_condition_maps_to_wfp_uint8() {
        let mut resources = FilterConditionResources::default();
        let condition = build_wfp_condition(
            &WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::IpProtocol,
                matcher: "equals".into(),
                value: "17".into(),
            },
            &mut resources,
        )
        .expect("IP protocol condition");

        assert_eq!(
            guid_string(condition.fieldKey),
            guid_string(FWPM_CONDITION_IP_PROTOCOL)
        );
        assert_eq!(condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.conditionValue.r#type, FWP_UINT8);
        assert_eq!(unsafe { condition.conditionValue.Anonymous.uint8 }, 17);
    }

    #[test]
    fn ipv4_address_conditions_map_to_wfp_v4_addr_mask() {
        let mut resources = FilterConditionResources::default();
        let local_condition = build_wfp_condition(
            &WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::IpLocalAddress,
                matcher: "equals".into(),
                value: "192.0.2.10".into(),
            },
            &mut resources,
        )
        .expect("IP local address condition");
        let remote_condition = build_wfp_condition(
            &WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::IpRemoteAddress,
                matcher: "equals".into(),
                value: "198.51.100.53".into(),
            },
            &mut resources,
        )
        .expect("IP remote address condition");

        assert_eq!(
            guid_string(local_condition.fieldKey),
            guid_string(FWPM_CONDITION_IP_LOCAL_ADDRESS)
        );
        assert_eq!(
            guid_string(remote_condition.fieldKey),
            guid_string(FWPM_CONDITION_IP_REMOTE_ADDRESS)
        );
        assert_eq!(local_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(remote_condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(local_condition.conditionValue.r#type, FWP_V4_ADDR_MASK);
        assert_eq!(remote_condition.conditionValue.r#type, FWP_V4_ADDR_MASK);

        let local_mask = unsafe {
            local_condition
                .conditionValue
                .Anonymous
                .v4AddrMask
                .as_ref()
                .expect("local v4 mask")
        };
        let remote_mask = unsafe {
            remote_condition
                .conditionValue
                .Anonymous
                .v4AddrMask
                .as_ref()
                .expect("remote v4 mask")
        };
        assert_eq!(local_mask.addr, u32::from(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(local_mask.mask, u32::MAX);
        assert_eq!(remote_mask.addr, u32::from(Ipv4Addr::new(198, 51, 100, 53)));
        assert_eq!(remote_mask.mask, u32::MAX);
    }

    #[test]
    fn filter_condition_validation_rejects_ipv4_address_on_ale_layers() {
        let spec = WindowsFirewallKillSwitchFilterSpec {
            key: "invalid-ale-ip-local-address".into(),
            name: "Invalid ALE IP local address".into(),
            role: WindowsFirewallKillSwitchFilterRole::PermitDnsEgress,
            sublayer: WindowsFirewallSublayerKind::DnsLeakPrevention,
            layer: WindowsFirewallKillSwitchLayer::AleAuthConnectV4,
            action: WindowsFirewallKillSwitchAction::Permit,
            weight: 25_000,
            conditions: vec![WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::IpLocalAddress,
                matcher: "equals".into(),
                value: "192.0.2.10".into(),
            }],
            rationale: "IP local address is not an ALE enforcement condition".into(),
        };

        let error = validate_filter_spec_conditions(&spec)
            .expect_err("IP local address should not be accepted on ALE layers");

        assert!(error.contains("IpLocalAddress"));
        assert!(error.contains("ALE_AUTH_CONNECT_V4"));
    }

    #[test]
    fn remote_port_condition_maps_to_wfp_uint16() {
        let mut resources = FilterConditionResources::default();
        let condition = build_wfp_condition(
            &WindowsFirewallKillSwitchCondition {
                field: WindowsFirewallKillSwitchConditionField::IpRemotePort,
                matcher: "equals".into(),
                value: "53".into(),
            },
            &mut resources,
        )
        .expect("remote port condition");

        assert_eq!(
            guid_string(condition.fieldKey),
            guid_string(FWPM_CONDITION_IP_REMOTE_PORT)
        );
        assert_eq!(condition.matchType, FWP_MATCH_EQUAL);
        assert_eq!(condition.conditionValue.r#type, FWP_UINT16);
        assert_eq!(unsafe { condition.conditionValue.Anonymous.uint16 }, 53);
    }

    #[test]
    fn filter_condition_validation_accepts_remote_port_on_supported_layers() {
        for layer in [
            WindowsFirewallKillSwitchLayer::AleAuthConnectV4,
            WindowsFirewallKillSwitchLayer::AleAuthConnectV6,
        ] {
            let spec = WindowsFirewallKillSwitchFilterSpec {
                key: format!("dns-leak-{}", layer.key_suffix()),
                name: "DNS leak".into(),
                role: WindowsFirewallKillSwitchFilterRole::BlockDnsLeak,
                sublayer: WindowsFirewallSublayerKind::DnsLeakPrevention,
                layer,
                action: WindowsFirewallKillSwitchAction::Block,
                weight: 1_000,
                conditions: vec![WindowsFirewallKillSwitchCondition {
                    field: WindowsFirewallKillSwitchConditionField::IpRemotePort,
                    matcher: "equals".into(),
                    value: "53".into(),
                }],
                rationale: "DNS leak test".into(),
            };

            validate_filter_spec_conditions(&spec).expect("remote port valid on DNS leak layer");
        }
    }

    fn test_net_event_record(
        layer_id: Option<u16>,
        layer_name: Option<&str>,
        dns_relevant: bool,
    ) -> WindowsFirewallNetEventRecord {
        WindowsFirewallNetEventRecord {
            event_type: "classify-drop".into(),
            event_type_code: FWPM_NET_EVENT_TYPE_CLASSIFY_DROP,
            timestamp_filetime: 0,
            flags: 0,
            ip_version: Some("ipv4".into()),
            ip_protocol: Some(17),
            local_addr: None,
            local_addr_raw: None,
            remote_addr: None,
            remote_addr_raw: None,
            local_port: Some(12345),
            remote_port: dns_relevant.then_some(53).or(Some(443)),
            scope_id: None,
            filter_id: None,
            layer_id,
            layer_name: layer_name.map(ToString::to_string),
            reauth_reason: None,
            ms_fwp_direction: None,
            is_loopback: None,
            dns_relevant,
        }
    }

    /// The observe decode is the exact inverse of the `add_filter` provider-data
    /// tag: a Egrio-owned filter round-trips its logical key. Exercises the pure
    /// decode helpers without opening the WFP engine.
    #[test]
    fn provider_data_tag_round_trips_the_logical_filter_key() {
        let mut provider_key = EGRIO_WFP_PROVIDER_KEY;
        let mut key_bytes = b"block-default-ale-auth-connect-v4".to_vec();
        let filter = FWPM_FILTER0 {
            providerKey: &mut provider_key,
            providerData: FWP_BYTE_BLOB {
                size: key_bytes.len() as u32,
                data: key_bytes.as_mut_ptr(),
            },
            ..FWPM_FILTER0::default()
        };

        assert!(filter_provider_is_egrio(&filter));
        assert_eq!(
            filter_provider_data_key(&filter).as_deref(),
            Some("block-default-ale-auth-connect-v4")
        );
    }

    #[test]
    fn observe_decode_skips_foreign_providers_and_rejects_invalid_egrio_filters() {
        // A foreign provider's filter is not ours.
        let mut foreign = GUID::from_u128(0x1);
        let filter = FWPM_FILTER0 {
            providerKey: &mut foreign,
            ..FWPM_FILTER0::default()
        };
        assert!(!filter_provider_is_egrio(&filter));
        assert_eq!(egrio_filter_key(&filter).unwrap(), None);

        // A provider-less filter (null provider key) is not ours and has no tag.
        let filter = FWPM_FILTER0::default();
        assert!(!filter_provider_is_egrio(&filter));
        assert_eq!(filter_provider_data_key(&filter), None);
        assert_eq!(egrio_filter_key(&filter).unwrap(), None);

        // A Egrio provider filter without the tag cannot be treated as absent.
        let mut provider_key = EGRIO_WFP_PROVIDER_KEY;
        let filter = FWPM_FILTER0 {
            filterId: 41,
            providerKey: &mut provider_key,
            ..FWPM_FILTER0::default()
        };
        let error = egrio_filter_key(&filter).unwrap_err();
        assert!(error.contains("filter 41"));

        // A non-UTF-8 provider-data blob is also an observation error.
        let mut provider_key = EGRIO_WFP_PROVIDER_KEY;
        let mut invalid = vec![0xff_u8, 0xfe, 0xfd];
        let filter = FWPM_FILTER0 {
            filterId: 42,
            providerKey: &mut provider_key,
            providerData: FWP_BYTE_BLOB {
                size: invalid.len() as u32,
                data: invalid.as_mut_ptr(),
            },
            ..FWPM_FILTER0::default()
        };
        assert!(filter_provider_is_egrio(&filter));
        assert_eq!(filter_provider_data_key(&filter), None);
        let error = egrio_filter_key(&filter).unwrap_err();
        assert!(error.contains("filter 42"));
    }

    #[test]
    fn guid_eq_distinguishes_the_provider_key_from_a_near_miss() {
        assert!(guid_eq(&EGRIO_WFP_PROVIDER_KEY, &EGRIO_WFP_PROVIDER_KEY));
        // The provider key with its last nibble flipped (…4a40 → …4a41).
        let near_miss = GUID::from_u128(0x2d606d68_04e0_4562_aa73_01fabf004a41);
        assert!(!guid_eq(&EGRIO_WFP_PROVIDER_KEY, &near_miss));
    }
}
