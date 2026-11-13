//! The read-only net-event diagnostic: what the engine recorded of dropped
//! connections, read for `egrio-node windows-wfp-net-events`.

use super::*;

pub fn windows_firewall_net_event_diagnostic_with_input(
    input: WindowsFirewallNetEventDiagnosticInput,
) -> WindowsFirewallNetEventDiagnosticReport {
    let events_requested = input.events_requested.clamp(1, 512);
    let mut report = WindowsFirewallNetEventDiagnosticReport {
        supported_os: true,
        read_only: true,
        engine_opened: false,
        enum_handle_opened: false,
        net_events_available: false,
        events_requested,
        event_window_start_filetime: input.event_window_start_filetime,
        event_window_end_filetime: input.event_window_end_filetime,
        enum_filter_conditions: input.enum_filter_conditions.clone(),
        events_returned: 0,
        dns_relevant_events: 0,
        dns_relevant_layers: Vec::new(),
        events: Vec::new(),
        blockers: Vec::new(),
        warnings: vec![
            "Read-only WFP net-event diagnostic: opens an engine session and enum handle, but does not enable net events or install filters"
                .into(),
        ],
    };
    if let (Some(start), Some(end)) = (
        input.event_window_start_filetime,
        input.event_window_end_filetime,
    ) {
        if start > end {
            report.blockers.push(format!(
                "WFP net-event diagnostic time window start {start} is after end {end}"
            ));
            return report;
        }
        report.warnings.push(format!(
            "Read-only WFP net-event diagnostic is bounded to FILETIME window {start}..{end}"
        ));
    }
    for condition in &input.enum_filter_conditions {
        if !net_event_enum_condition_field_supported(&condition.field) {
            report.blockers.push(format!(
                "WFP net-event enum template does not support condition field {:?}",
                condition.field
            ));
        }
    }
    if !report.blockers.is_empty() {
        report.blockers.sort();
        report.blockers.dedup();
        return report;
    }

    let engine = match WfpEngine::open_read_only("Egrio WFP net-event diagnostic") {
        Ok(engine) => {
            report.engine_opened = true;
            engine
        }
        Err(error) => {
            report.blockers.push(error);
            return report;
        }
    };

    let mut template_resources = FilterConditionResources::default();
    let mut template_conditions = match input
        .enum_filter_conditions
        .iter()
        .map(|condition| build_wfp_condition(condition, &mut template_resources))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(conditions) => conditions,
        Err(error) => {
            report.blockers.push(error);
            return report;
        }
    };
    let has_template = input.event_window_start_filetime.is_some()
        || input.event_window_end_filetime.is_some()
        || !template_conditions.is_empty();
    let template = has_template.then(|| FWPM_NET_EVENT_ENUM_TEMPLATE0 {
        startTime: filetime_from_u64(input.event_window_start_filetime.unwrap_or_default()),
        endTime: filetime_from_u64(input.event_window_end_filetime.unwrap_or_default()),
        numFilterConditions: template_conditions.len() as u32,
        filterCondition: template_conditions.as_mut_ptr(),
    });

    let enum_handle = match engine.create_net_event_enum_handle(template.as_ref()) {
        Ok(enum_handle) => {
            report.enum_handle_opened = true;
            report.net_events_available = true;
            enum_handle
        }
        Err(status) if status == FWP_E_NET_EVENTS_DISABLED as u32 => {
            report.warnings.push(
                "WFP net events are disabled on this machine; leaving them disabled for read-only diagnostics"
                    .into(),
            );
            return report;
        }
        Err(status) => {
            report
                .blockers
                .push(wfp_status_error("create WFP net-event enum handle", status));
            return report;
        }
    };

    match enum_handle.enumerate(events_requested) {
        Ok(events) => {
            report.events_returned = events.len() as u32;
            report.dns_relevant_events = events.iter().filter(|event| event.dns_relevant).count();
            report.dns_relevant_layers = net_event_dns_relevant_layers(&events);
            report.events = events;
        }
        Err(status) if status == FWP_E_NET_EVENTS_DISABLED as u32 => {
            report.net_events_available = false;
            report.warnings.push(
                "WFP net events became unavailable during enumeration; leaving system settings unchanged"
                    .into(),
            );
        }
        Err(status) => report
            .blockers
            .push(wfp_status_error("enumerate WFP net events", status)),
    }

    report
}

pub(super) fn net_event_enum_condition_field_supported(
    field: &WindowsFirewallKillSwitchConditionField,
) -> bool {
    matches!(
        field,
        WindowsFirewallKillSwitchConditionField::AleAppId
            | WindowsFirewallKillSwitchConditionField::IpProtocol
            | WindowsFirewallKillSwitchConditionField::IpLocalAddress
            | WindowsFirewallKillSwitchConditionField::IpRemoteAddress
            | WindowsFirewallKillSwitchConditionField::IpRemotePort
    )
}

pub(super) struct WfpNetEventEnumHandle<'a> {
    pub(super) engine: &'a WfpEngine,
    pub(super) handle: HANDLE,
}

impl WfpNetEventEnumHandle<'_> {
    fn enumerate(&self, events_requested: u32) -> Result<Vec<WindowsFirewallNetEventRecord>, u32> {
        let mut entries: *mut *mut FWPM_NET_EVENT5 = ptr::null_mut();
        let mut entries_returned = 0_u32;
        let status = unsafe {
            FwpmNetEventEnum5(
                self.engine.handle,
                self.handle,
                events_requested,
                &mut entries,
                &mut entries_returned,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(status);
        }

        let mut records = Vec::with_capacity(entries_returned as usize);
        if !entries.is_null() {
            let entry_slice =
                unsafe { std::slice::from_raw_parts(entries, entries_returned as usize) };
            for event in entry_slice
                .iter()
                .filter_map(|event| unsafe { event.as_ref() })
            {
                records.push(net_event_record(event));
            }
            let mut memory = entries as *mut c_void;
            unsafe { FwpmFreeMemory0(&mut memory) };
        }

        Ok(records)
    }
}

impl Drop for WfpNetEventEnumHandle<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let _ = unsafe { FwpmNetEventDestroyEnumHandle0(self.engine.handle, self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

fn net_event_record(event: &FWPM_NET_EVENT5) -> WindowsFirewallNetEventRecord {
    let header = &event.header;
    let ip_version = net_event_ip_version_name(header.ipVersion).map(ToString::to_string);
    let ip_protocol = flag_value(
        header.flags,
        FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET,
        header.ipProtocol,
    );
    let (local_addr, local_addr_raw) = net_event_addr(
        header.flags,
        FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET,
        header.ipVersion,
        || unsafe { header.Anonymous1.localAddrV4 },
        || unsafe { header.Anonymous1.localAddrV6.byteArray16 },
    );
    let (remote_addr, remote_addr_raw) = net_event_addr(
        header.flags,
        FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET,
        header.ipVersion,
        || unsafe { header.Anonymous2.remoteAddrV4 },
        || unsafe { header.Anonymous2.remoteAddrV6.byteArray16 },
    );
    let local_port = flag_value(
        header.flags,
        FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET,
        header.localPort,
    );
    let remote_port = flag_value(
        header.flags,
        FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET,
        header.remotePort,
    );
    let scope_id = flag_value(
        header.flags,
        FWPM_NET_EVENT_FLAG_SCOPE_ID_SET,
        header.scopeId,
    );
    let classify = unsafe { net_event_classify_details(event) };
    let dns_relevant = net_event_is_dns_relevant(local_port, remote_port, ip_protocol);

    WindowsFirewallNetEventRecord {
        event_type: net_event_type_name(event.r#type).into(),
        event_type_code: event.r#type,
        timestamp_filetime: filetime_to_u64(header.timeStamp),
        flags: header.flags,
        ip_version,
        ip_protocol,
        local_addr,
        local_addr_raw,
        remote_addr,
        remote_addr_raw,
        local_port,
        remote_port,
        scope_id,
        filter_id: classify.filter_id,
        layer_id: classify.layer_id,
        layer_name: classify
            .layer_id
            .and_then(net_event_fwps_layer_name)
            .map(ToString::to_string),
        reauth_reason: classify.reauth_reason,
        ms_fwp_direction: classify.ms_fwp_direction,
        is_loopback: classify.is_loopback,
        dns_relevant,
    }
}

pub(super) fn net_event_dns_relevant_layers(
    events: &[WindowsFirewallNetEventRecord],
) -> Vec<WindowsFirewallNetEventLayerSummary> {
    let mut summaries = Vec::<WindowsFirewallNetEventLayerSummary>::new();
    for event in events.iter().filter(|event| event.dns_relevant) {
        if let Some(summary) = summaries.iter_mut().find(|summary| {
            summary.layer_id == event.layer_id && summary.layer_name == event.layer_name
        }) {
            summary.dns_relevant_events += 1;
        } else {
            summaries.push(WindowsFirewallNetEventLayerSummary {
                layer_id: event.layer_id,
                layer_name: event.layer_name.clone(),
                dns_relevant_events: 1,
            });
        }
    }
    summaries.sort_by(|left, right| {
        left.layer_id
            .cmp(&right.layer_id)
            .then_with(|| left.layer_name.cmp(&right.layer_name))
    });
    summaries
}

#[derive(Default)]
struct NetEventClassifyDetails {
    filter_id: Option<u64>,
    layer_id: Option<u16>,
    reauth_reason: Option<u32>,
    ms_fwp_direction: Option<u32>,
    is_loopback: Option<bool>,
}

unsafe fn net_event_classify_details(event: &FWPM_NET_EVENT5) -> NetEventClassifyDetails {
    match event.r#type {
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP => {
            let classify = unsafe { event.Anonymous.classifyDrop.as_ref() };
            classify
                .map(|classify| NetEventClassifyDetails {
                    filter_id: Some(classify.filterId),
                    layer_id: Some(classify.layerId),
                    reauth_reason: Some(classify.reauthReason),
                    ms_fwp_direction: Some(classify.msFwpDirection),
                    is_loopback: Some(classify.isLoopback != 0),
                })
                .unwrap_or_default()
        }
        FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW => {
            let classify = unsafe { event.Anonymous.classifyAllow.as_ref() };
            classify
                .map(|classify| NetEventClassifyDetails {
                    filter_id: Some(classify.filterId),
                    layer_id: Some(classify.layerId),
                    reauth_reason: Some(classify.reauthReason),
                    ms_fwp_direction: Some(classify.msFwpDirection),
                    is_loopback: Some(classify.isLoopback != 0),
                })
                .unwrap_or_default()
        }
        _ => NetEventClassifyDetails::default(),
    }
}

pub(super) fn net_event_addr<F4, F6>(
    flags: u32,
    addr_flag: u32,
    ip_version: FWP_IP_VERSION,
    read_v4: F4,
    read_v6: F6,
) -> (Option<String>, Option<String>)
where
    F4: FnOnce() -> u32,
    F6: FnOnce() -> [u8; 16],
{
    if flags & addr_flag == 0 {
        return (None, None);
    }

    match ip_version {
        FWP_IP_VERSION_V4 => {
            let raw = read_v4();
            (
                Some(Ipv4Addr::from(raw.to_be_bytes()).to_string()),
                Some(format!("0x{raw:08x}")),
            )
        }
        FWP_IP_VERSION_V6 => {
            let raw = read_v6();
            (
                Some(Ipv6Addr::from(raw).to_string()),
                Some(
                    raw.iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(""),
                ),
            )
        }
        _ => (None, None),
    }
}

fn flag_value<T: Copy>(flags: u32, flag: u32, value: T) -> Option<T> {
    (flags & flag != 0).then_some(value)
}

pub(super) fn filetime_to_u64(filetime: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    ((filetime.dwHighDateTime as u64) << 32) | filetime.dwLowDateTime as u64
}

pub(super) fn filetime_from_u64(value: u64) -> FILETIME {
    FILETIME {
        dwLowDateTime: value as u32,
        dwHighDateTime: (value >> 32) as u32,
    }
}

fn net_event_ip_version_name(ip_version: FWP_IP_VERSION) -> Option<&'static str> {
    match ip_version {
        FWP_IP_VERSION_V4 => Some("ipv4"),
        FWP_IP_VERSION_V6 => Some("ipv6"),
        FWP_IP_VERSION_NONE => None,
        _ => Some("unknown"),
    }
}

pub(super) fn net_event_type_name(event_type: FWPM_NET_EVENT_TYPE) -> &'static str {
    match event_type {
        FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE => "ikeext-mm-failure",
        FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE => "ikeext-qm-failure",
        FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE => "ikeext-em-failure",
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP => "classify-drop",
        FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP => "ipsec-kernel-drop",
        FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP => "ipsec-dosp-drop",
        FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW => "classify-allow",
        FWPM_NET_EVENT_TYPE_CAPABILITY_DROP => "capability-drop",
        FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW => "capability-allow",
        FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC => "classify-drop-mac",
        FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL => "lpm-packet-arrival",
        _ => "unknown",
    }
}

pub(super) fn net_event_fwps_layer_name(layer_id: u16) -> Option<&'static str> {
    match layer_id {
        FWPS_LAYER_OUTBOUND_TRANSPORT_V4_ID => Some("FWPS_LAYER_OUTBOUND_TRANSPORT_V4"),
        FWPS_LAYER_OUTBOUND_TRANSPORT_V6_ID => Some("FWPS_LAYER_OUTBOUND_TRANSPORT_V6"),
        FWPS_LAYER_ALE_AUTH_CONNECT_V4_ID => Some("FWPS_LAYER_ALE_AUTH_CONNECT_V4"),
        FWPS_LAYER_ALE_AUTH_CONNECT_V6_ID => Some("FWPS_LAYER_ALE_AUTH_CONNECT_V6"),
        _ => None,
    }
}

pub(super) fn net_event_is_dns_relevant(
    local_port: Option<u16>,
    remote_port: Option<u16>,
    _ip_protocol: Option<u8>,
) -> bool {
    local_port == Some(53) || remote_port == Some(53)
}
