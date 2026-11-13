use super::{WindowsFirewallNetEventDiagnosticInput, WindowsFirewallNetEventDiagnosticReport};

pub fn windows_firewall_net_event_diagnostic_with_input(
    input: WindowsFirewallNetEventDiagnosticInput,
) -> WindowsFirewallNetEventDiagnosticReport {
    WindowsFirewallNetEventDiagnosticReport {
        supported_os: false,
        read_only: true,
        engine_opened: false,
        enum_handle_opened: false,
        net_events_available: false,
        events_requested: input.events_requested,
        event_window_start_filetime: input.event_window_start_filetime,
        event_window_end_filetime: input.event_window_end_filetime,
        enum_filter_conditions: input.enum_filter_conditions,
        events_returned: 0,
        dns_relevant_events: 0,
        dns_relevant_layers: Vec::new(),
        events: Vec::new(),
        blockers: vec!["Windows WFP net-event diagnostics are only supported on Windows".into()],
        warnings: Vec::new(),
    }
}
