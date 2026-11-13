use std::io::{self, Write};

use egrio_platform_windows::{
    windows_firewall_net_event_diagnostic_with_input, WindowsFirewallNetEventDiagnosticInput,
};

pub(crate) fn print_wfp_net_events(
    max_events_arg: Option<String>,
    window_start_arg: Option<String>,
    window_end_arg: Option<String>,
) -> Result<(), String> {
    let input = wfp_net_event_diagnostic_input(max_events_arg, window_start_arg, window_end_arg)?;

    print_json(&windows_firewall_net_event_diagnostic_with_input(input))
}

pub(crate) fn wfp_net_event_diagnostic_input(
    max_events_arg: Option<String>,
    window_start_arg: Option<String>,
    window_end_arg: Option<String>,
) -> Result<WindowsFirewallNetEventDiagnosticInput, String> {
    let events_requested = optional_dash_arg(max_events_arg)
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|error| format!("invalid windows-wfp-net-events max-events: {error}"))
        })
        .transpose()?
        .unwrap_or(64);
    let window_start = parse_optional_filetime(window_start_arg, "window-start-filetime")?;
    let window_end = parse_optional_filetime(window_end_arg, "window-end-filetime")?;
    if window_start.is_some() != window_end.is_some() {
        return Err(
            "windows-wfp-net-events requires both window-start-filetime and window-end-filetime"
                .into(),
        );
    }
    if let (Some(start), Some(end)) = (window_start, window_end) {
        if start > end {
            return Err(format!(
                "invalid windows-wfp-net-events FILETIME window: start {start} is after end {end}"
            ));
        }
    }

    Ok(WindowsFirewallNetEventDiagnosticInput {
        events_requested,
        event_window_start_filetime: window_start,
        event_window_end_filetime: window_end,
        enum_filter_conditions: Vec::new(),
    })
}

fn parse_optional_filetime(arg: Option<String>, label: &str) -> Result<Option<u64>, String> {
    optional_dash_arg(arg)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid windows-wfp-net-events {label}: {error}"))
        })
        .transpose()
}

/// Treats a literal `-` argument as "not provided" so positional CLI args can
/// be skipped.
fn optional_dash_arg(arg: Option<String>) -> Option<String> {
    arg.map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty() && value != "-")
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let document = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{document}");
    io::stdout().flush().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wfp_net_event_cli_input_defaults_without_window() {
        let input = wfp_net_event_diagnostic_input(None, None, None).expect("default input");

        assert_eq!(input.events_requested, 64);
        assert_eq!(input.event_window_start_filetime, None);
        assert_eq!(input.event_window_end_filetime, None);
    }

    #[test]
    fn wfp_net_event_cli_input_accepts_bounded_filetime_window() {
        let input = wfp_net_event_diagnostic_input(
            Some("512".into()),
            Some("100".into()),
            Some("200".into()),
        )
        .expect("bounded input");

        assert_eq!(input.events_requested, 512);
        assert_eq!(input.event_window_start_filetime, Some(100));
        assert_eq!(input.event_window_end_filetime, Some(200));

        let dashed =
            wfp_net_event_diagnostic_input(Some("-".into()), Some("-".into()), Some("-".into()))
                .expect("dash omits optional args");
        assert_eq!(dashed.events_requested, 64);
        assert_eq!(dashed.event_window_start_filetime, None);
        assert_eq!(dashed.event_window_end_filetime, None);
    }

    #[test]
    fn wfp_net_event_cli_input_rejects_incomplete_or_reversed_window() {
        let incomplete =
            wfp_net_event_diagnostic_input(None, Some("100".into()), None).expect_err("pair");
        assert!(incomplete.contains("requires both"));

        let reversed = wfp_net_event_diagnostic_input(None, Some("200".into()), Some("100".into()))
            .expect_err("reversed window");
        assert!(reversed.contains("start 200 is after end 100"));

        let invalid =
            wfp_net_event_diagnostic_input(None, Some("not-a-filetime".into()), Some("200".into()))
                .expect_err("invalid FILETIME");
        assert!(invalid.contains("window-start-filetime"));
    }
}
