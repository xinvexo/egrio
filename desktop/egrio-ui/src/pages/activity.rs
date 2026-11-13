//! The activity page: live traffic first, then where it leaves. The
//! connection counts and the local proxy address sit under the chart; the
//! egress card shows the addresses, location and operator the Core's path
//! reaches once a capture layer is on and the mode goes through a proxy.

use egrio_core::TrafficPolicyMode;
use egrio_desktop::models::PublicIpInfo;
use egrio_desktop::network_probe::PublicIpAddressInfo;

use crate::chart;
use crate::format;
use crate::node::{
    caption, card, chart as chart_node, column, fact, facts, field, fields, heading, paragraph,
    row, spacer, symbol, text, Chart, Icon, Node, TextStyle, Tone,
};
use crate::state::{Remote, State};
use crate::text::Text;

/// Whether the egress is worth looking up: a capture layer is on and the
/// mode sends traffic through a proxy.
pub fn egress_useful(state: &State) -> bool {
    let capturing = state
        .capture
        .as_ref()
        .is_some_and(|status| status.layers.system_proxy || status.layers.tun);
    let proxied = match state.active_profile.ready().and_then(Option::as_ref) {
        Some(profile) => match profile.traffic_policy_mode {
            TrafficPolicyMode::Direct => false,
            TrafficPolicyMode::Global => {
                !is_terminal_outbound(profile.global_outbound.as_deref().unwrap_or_default())
            }
            TrafficPolicyMode::Rule => true,
        },
        None => true,
    };
    capturing && proxied
}

/// A profile-wide terminal outbound sends nothing through a proxy.
fn is_terminal_outbound(outbound: &str) -> bool {
    matches!(
        outbound.trim().to_ascii_uppercase().as_str(),
        "DIRECT" | "REJECT" | "REJECT-DROP" | "BLOCK"
    )
}

fn rate_readout(label: &str, rate: f64, icon: Icon, tone: Tone) -> Node {
    let (figure, unit) = format::rate(rate);
    row(
        8.0,
        vec![
            symbol(icon, tone),
            column(
                2.0,
                vec![
                    caption(label),
                    row(
                        4.0,
                        vec![text(figure, TextStyle::Figure, tone), caption(unit)],
                    ),
                ],
            ),
        ],
    )
}

fn traffic_card(state: &State) -> Node {
    let text_set = state.text();
    let latest = state.series.latest();
    let paths = chart::view_paths(&state.series);
    let (download_figure, download_unit) = format::rate(latest.download);
    let (upload_figure, upload_unit) = format::rate(latest.upload);
    let totals = state.totals.ready();
    let count = |value: Option<u64>| match (&state.totals, value) {
        (_, Some(value)) => value.to_string(),
        (Remote::Loading, None) => text_set.loading().to_string(),
        (Remote::Failed(_), None) => text_set.fetch_failed().to_string(),
        _ => "—".to_string(),
    };
    let listen = state
        .core
        .as_ref()
        .and_then(|core| core.listen_addr.clone());
    let mut proxy = fact(
        text_set.local_proxy(),
        listen.clone().unwrap_or_else(|| {
            if state.core.is_none() {
                text_set.loading()
            } else {
                text_set.not_listening()
            }
            .to_string()
        }),
    );
    proxy.mono = listen.is_some();
    proxy.warning = state.port_fallback().map(|fallback| {
        format!(
            "{}\n{}",
            text_set.port_fallback(fallback.requested, fallback.actual),
            fallback.detail(text_set)
        )
    });
    card(vec![
        row(
            12.0,
            vec![
                heading(text_set.traffic_title()),
                spacer(),
                text(
                    text_set.peak(&format::rounded_rate(state.series.peak_in_view())),
                    TextStyle::Caption,
                    Tone::Faint,
                ),
            ],
        ),
        row(
            40.0,
            vec![
                rate_readout(
                    text_set.download(),
                    latest.download,
                    Icon::Download,
                    Tone::Accent,
                ),
                rate_readout(
                    text_set.upload(),
                    latest.upload,
                    Icon::Upload,
                    Tone::Success,
                ),
            ],
        ),
        chart_node(Chart {
            download_area: paths.download_area,
            download_line: paths.download,
            upload_area: paths.upload_area,
            upload_line: paths.upload,
            description: text_set.chart_description(
                &format!("{download_figure} {download_unit}"),
                &format!("{upload_figure} {upload_unit}"),
            ),
        })
        .grow(),
        facts(vec![
            fact(
                text_set.active_connections(),
                count(totals.map(|totals| totals.active_connections)),
            ),
            fact(
                text_set.process_count(),
                count(totals.map(|totals| totals.processes)),
            ),
            proxy,
        ]),
    ])
    .height(320.0)
    .key("traffic")
}

fn location(info: &PublicIpAddressInfo) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in [&info.city, &info.region, &info.country]
        .into_iter()
        .flatten()
    {
        // Drop duplicates like "Hong Kong, Hong Kong, Hong Kong".
        if !parts.contains(&part.as_str()) {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        "—".into()
    } else {
        parts.join(", ")
    }
}

fn provider(info: &PublicIpAddressInfo) -> String {
    let name = info.isp.as_deref().or(info.organization.as_deref());
    let asn = info.asn.map(|asn| format!("AS{asn}"));
    let joined: Vec<String> = name.map(str::to_string).into_iter().chain(asn).collect();
    if joined.is_empty() {
        "—".into()
    } else {
        joined.join(" · ")
    }
}

fn egress(info: &PublicIpInfo, text_set: Text) -> Node {
    let Some(primary) = info.ipv4.as_ref().or(info.ipv6.as_ref()) else {
        return caption(text_set.egress_no_address());
    };
    let differ = matches!((&info.ipv4, &info.ipv6), (Some(v4), Some(v6)) if v4.ip != v6.ip);
    let family = if info.ipv4.is_some() { "IPv4" } else { "IPv6" };
    let qualify = |label: &str| {
        if differ {
            text_set.qualified(label, family)
        } else {
            label.to_string()
        }
    };
    let mut addresses = field(text_set.egress_ip(), "");
    addresses.values = [&info.ipv4, &info.ipv6]
        .into_iter()
        .flatten()
        .map(|entry| entry.ip.clone())
        .collect();
    addresses.mono = true;
    fields(
        3,
        vec![
            addresses,
            field(qualify(text_set.egress_location()), location(primary)),
            field(qualify(text_set.egress_provider()), provider(primary)),
        ],
    )
}

fn egress_card(state: &State) -> Node {
    let text_set = state.text();
    let body = if egress_useful(state) {
        match &state.public_ip {
            Remote::Ready(info) => egress(info, text_set),
            Remote::Loading => caption(text_set.loading()),
            Remote::Failed(_) => caption(text_set.fetch_failed()),
        }
    } else {
        let capturing = state
            .capture
            .as_ref()
            .is_some_and(|status| status.layers.system_proxy || status.layers.tun);
        paragraph(
            if capturing {
                text_set.egress_direct()
            } else {
                text_set.egress_idle()
            },
            Tone::Muted,
        )
    };
    card(vec![heading(text_set.egress_title()), body]).key("egress")
}

pub fn view(state: &State) -> Node {
    column(12.0, vec![traffic_card(state), egress_card(state)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_outbounds_need_no_egress() {
        assert!(is_terminal_outbound(" direct "));
        assert!(is_terminal_outbound("REJECT"));
        assert!(!is_terminal_outbound("Proxy"));
    }

    #[test]
    fn locations_drop_repeated_parts() {
        let info = PublicIpAddressInfo {
            ip: "1.2.3.4".into(),
            isp: None,
            organization: Some("Example".into()),
            asn: Some(64500),
            city: Some("Hong Kong".into()),
            region: Some("Hong Kong".into()),
            country: Some("Hong Kong".into()),
            source: "test".into(),
        };
        assert_eq!(location(&info), "Hong Kong");
        assert_eq!(provider(&info), "Example · AS64500");
    }
}
