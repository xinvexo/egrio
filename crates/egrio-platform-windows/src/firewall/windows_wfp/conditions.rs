//! A plan's filter conditions as the engine takes them: each condition's
//! WFP field, match type and value, and the layers it is valid on.

use super::*;

pub(super) fn validate_filter_spec_conditions(
    spec: &WindowsFirewallKillSwitchFilterSpec,
) -> Result<(), String> {
    for condition in &spec.conditions {
        if !spec.layer.supports_condition_field(&condition.field) {
            return Err(format!(
                "WFP condition {:?} is not supported on {}",
                condition.field,
                spec.layer.display_name()
            ));
        }
    }

    Ok(())
}

#[derive(Default)]
pub(super) struct FilterConditionResources {
    app_ids: Vec<AppIdBlob>,
    v4_addr_masks: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6_addr_masks: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
}

struct AppIdBlob {
    ptr: *mut FWP_BYTE_BLOB,
}

impl Drop for AppIdBlob {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            let mut memory = self.ptr as *mut c_void;
            unsafe { FwpmFreeMemory0(&mut memory) };
            self.ptr = ptr::null_mut();
        }
    }
}

pub(super) fn build_wfp_condition(
    condition: &WindowsFirewallKillSwitchCondition,
    resources: &mut FilterConditionResources,
) -> Result<FWPM_FILTER_CONDITION0, String> {
    match condition.field {
        WindowsFirewallKillSwitchConditionField::AleAppId => {
            if condition.matcher != "equals-app-id-from-path" {
                return Err(format!(
                    "unsupported ALE_APP_ID matcher '{}'",
                    condition.matcher
                ));
            }
            let app_id = app_id_blob_from_path(&condition.value)?;
            let app_id_ptr = app_id.ptr;
            resources.app_ids.push(app_id);
            Ok(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_APP_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_BLOB_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteBlob: app_id_ptr,
                    },
                },
            })
        }
        WindowsFirewallKillSwitchConditionField::InterfaceIndex => {
            if condition.matcher != "equals" {
                return Err(format!(
                    "unsupported interface-index matcher '{}'",
                    condition.matcher
                ));
            }
            let interface_index = condition.value.parse::<u32>().map_err(|error| {
                format!(
                    "invalid WFP interface index condition '{}': {error}",
                    condition.value
                )
            })?;
            Ok(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_INTERFACE_INDEX,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: interface_index,
                    },
                },
            })
        }
        WindowsFirewallKillSwitchConditionField::InterfaceType => {
            if condition.matcher != "equals" {
                return Err(format!(
                    "unsupported interface-type matcher '{}'",
                    condition.matcher
                ));
            }
            let interface_type = condition.value.parse::<u32>().map_err(|error| {
                format!(
                    "invalid WFP interface type condition '{}': {error}",
                    condition.value
                )
            })?;
            Ok(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_INTERFACE_TYPE,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint32: interface_type,
                    },
                },
            })
        }
        WindowsFirewallKillSwitchConditionField::IpProtocol => {
            if condition.matcher != "equals" {
                return Err(format!(
                    "unsupported IP protocol matcher '{}'",
                    condition.matcher
                ));
            }
            let protocol = condition.value.parse::<u8>().map_err(|error| {
                format!(
                    "invalid WFP IP protocol condition '{}': {error}",
                    condition.value
                )
            })?;
            Ok(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: protocol },
                },
            })
        }
        WindowsFirewallKillSwitchConditionField::IpLocalAddress => {
            build_wfp_ipv4_address_condition(
                condition,
                resources,
                FWPM_CONDITION_IP_LOCAL_ADDRESS,
                "IP local address",
            )
        }
        WindowsFirewallKillSwitchConditionField::IpRemoteAddress => {
            build_wfp_ipv4_address_condition(
                condition,
                resources,
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                "IP remote address",
            )
        }
        WindowsFirewallKillSwitchConditionField::IpRemotePort => {
            if condition.matcher != "equals" {
                return Err(format!(
                    "unsupported IP remote port matcher '{}'",
                    condition.matcher
                ));
            }
            let remote_port = condition.value.parse::<u16>().map_err(|error| {
                format!(
                    "invalid WFP remote port condition '{}': {error}",
                    condition.value
                )
            })?;
            Ok(FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint16: remote_port,
                    },
                },
            })
        }
    }
}

fn build_wfp_ipv4_address_condition(
    condition: &WindowsFirewallKillSwitchCondition,
    resources: &mut FilterConditionResources,
    field_key: GUID,
    label: &str,
) -> Result<FWPM_FILTER_CONDITION0, String> {
    if condition.matcher != "equals" {
        return Err(format!(
            "unsupported {label} matcher '{}'",
            condition.matcher
        ));
    }
    let (address, prefix_length) = parse_wfp_address_condition_value(&condition.value, label)?;
    match address {
        std::net::IpAddr::V4(address) => {
            let mask = if prefix_length == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_length))
            };
            resources.v4_addr_masks.push(Box::new(FWP_V4_ADDR_AND_MASK {
                addr: u32::from(address),
                mask,
            }));
            let v4_addr_mask = resources
                .v4_addr_masks
                .last_mut()
                .expect("just inserted WFP IPv4 address mask")
                .as_mut() as *mut FWP_V4_ADDR_AND_MASK;

            Ok(FWPM_FILTER_CONDITION0 {
                fieldKey: field_key,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v4AddrMask: v4_addr_mask,
                    },
                },
            })
        }
        std::net::IpAddr::V6(address) => {
            resources.v6_addr_masks.push(Box::new(FWP_V6_ADDR_AND_MASK {
                addr: address.octets(),
                prefixLength: prefix_length,
            }));
            let v6_addr_mask = resources
                .v6_addr_masks
                .last_mut()
                .expect("just inserted WFP IPv6 address mask")
                .as_mut() as *mut FWP_V6_ADDR_AND_MASK;

            Ok(FWPM_FILTER_CONDITION0 {
                fieldKey: field_key,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V6_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        v6AddrMask: v6_addr_mask,
                    },
                },
            })
        }
    }
}

/// Parses `address` or `address/prefix` condition values for both IP
/// families. A bare address means an exact-host match.
fn parse_wfp_address_condition_value(
    value: &str,
    label: &str,
) -> Result<(std::net::IpAddr, u8), String> {
    let (address_text, prefix_text) = match value.rsplit_once('/') {
        Some((address_text, prefix_text)) => (address_text, Some(prefix_text)),
        None => (value, None),
    };
    let address = address_text
        .parse::<std::net::IpAddr>()
        .map_err(|error| format!("invalid WFP {label} condition '{value}': {error}"))?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    let prefix_length = match prefix_text {
        Some(prefix_text) => prefix_text
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= max_prefix)
            .ok_or_else(|| format!("invalid WFP {label} prefix in condition '{value}'"))?,
        None => max_prefix,
    };
    Ok((address, prefix_length))
}

fn app_id_blob_from_path(path: &str) -> Result<AppIdBlob, String> {
    let path = wide_null(path);
    let mut app_id = ptr::null_mut();
    ensure_wfp_ok(
        unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut app_id) },
        "resolve WFP app id from executable path",
    )?;

    Ok(AppIdBlob { ptr: app_id })
}

pub(super) fn layer_key(layer: &WindowsFirewallKillSwitchLayer) -> GUID {
    match layer {
        WindowsFirewallKillSwitchLayer::AleAuthConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        WindowsFirewallKillSwitchLayer::AleAuthConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    }
}

pub(super) fn action_type(action: &WindowsFirewallKillSwitchAction) -> u32 {
    match action {
        WindowsFirewallKillSwitchAction::Permit => FWP_ACTION_PERMIT,
        WindowsFirewallKillSwitchAction::Block => FWP_ACTION_BLOCK,
    }
}
