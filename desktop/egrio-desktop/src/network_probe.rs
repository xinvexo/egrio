use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use reqwest::header::USER_AGENT;
use serde::{Deserialize, Serialize};

const IPV4_ADDRESS_ENDPOINTS: &[&str] = &[
    "https://ipv4.icanhazip.com/",
    "https://api.ipify.org/",
    "https://4.ident.me/",
];
const IPV6_ADDRESS_ENDPOINTS: &[&str] = &[
    "https://ipv6.icanhazip.com/",
    "https://api6.ipify.org/",
    "https://6.ident.me/",
];
const PUBLIC_IP_INFO_ENDPOINT: &str = "https://ipwho.is/";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicIpInfo {
    pub ipv4: Option<PublicIpAddressInfo>,
    pub ipv6: Option<PublicIpAddressInfo>,
    pub ipv4_error: Option<String>,
    pub ipv6_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicIpAddressInfo {
    pub ip: String,
    pub isp: Option<String>,
    pub organization: Option<String>,
    pub asn: Option<u32>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub source: String,
}

#[derive(Debug, Default, Deserialize)]
struct IpWhoIsConnection {
    asn: Option<u32>,
    isp: Option<String>,
    org: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpWhoIsResponse {
    success: Option<bool>,
    message: Option<String>,
    ip: Option<String>,
    city: Option<String>,
    region: Option<String>,
    country: Option<String>,
    connection: Option<IpWhoIsConnection>,
}

#[derive(Clone, Copy)]
struct PublicIpProbeEndpoints<'a> {
    ipv4: &'a [&'a str],
    ipv6: &'a [&'a str],
    info: Option<&'a str>,
}

impl Default for PublicIpProbeEndpoints<'static> {
    fn default() -> Self {
        Self {
            ipv4: IPV4_ADDRESS_ENDPOINTS,
            ipv6: IPV6_ADDRESS_ENDPOINTS,
            info: Some(PUBLIC_IP_INFO_ENDPOINT),
        }
    }
}

pub async fn get_public_ip_info(core_listen_addr: &str) -> Result<PublicIpInfo, String> {
    let client = public_ip_client(core_listen_addr)?;
    get_public_ip_info_with(&client, PublicIpProbeEndpoints::default()).await
}

fn public_ip_client(core_listen_addr: &str) -> Result<reqwest::Client, String> {
    let listen_addr = core_listen_addr.parse::<SocketAddr>().map_err(|error| {
        format!("invalid native Core listen address '{core_listen_addr}': {error}")
    })?;
    // The address comes from the running Core, so an explicit interface bind
    // is local too. Only wildcard binds need a loopback dial destination.
    let listen_addr = egrio_core::inbound::local_listener_address(listen_addr);

    let proxy = reqwest::Proxy::all(format!("http://{listen_addr}"))
        .map_err(|error| format!("invalid native Core proxy address: {error}"))?;
    reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .no_proxy()
        .proxy(proxy)
        .build()
        .map_err(|error| error.to_string())
}

async fn get_public_ip_info_with(
    client: &reqwest::Client,
    endpoints: PublicIpProbeEndpoints<'_>,
) -> Result<PublicIpInfo, String> {
    let (ipv4, ipv6) = tokio::join!(
        probe_address_family(client, endpoints.ipv4, endpoints.info, false),
        probe_address_family(client, endpoints.ipv6, endpoints.info, true),
    );

    let (ipv4, ipv4_error) = split_family_probe(ipv4);
    let (ipv6, ipv6_error) = split_family_probe(ipv6);
    Ok(PublicIpInfo {
        ipv4,
        ipv6,
        ipv4_error,
        ipv6_error,
    })
}

fn split_family_probe(
    result: Result<(PublicIpAddressInfo, Option<String>), String>,
) -> (Option<PublicIpAddressInfo>, Option<String>) {
    match result {
        // A probe can succeed at resolving the address yet still carry a
        // warning (the metadata lookup saw a different egress); the address is
        // kept and the warning rides in the same error slot the UI already
        // renders as hover detail.
        Ok((info, warning)) => (Some(info), warning),
        Err(error) => (None, Some(error)),
    }
}

async fn probe_address_family(
    client: &reqwest::Client,
    address_endpoints: &[&str],
    info_endpoint: Option<&str>,
    expect_ipv6: bool,
) -> Result<(PublicIpAddressInfo, Option<String>), String> {
    let family = if expect_ipv6 { "IPv6" } else { "IPv4" };
    if address_endpoints.is_empty() {
        return Err(format!("no {family} address lookup endpoints configured"));
    }

    let mut errors = Vec::with_capacity(address_endpoints.len());
    for address_endpoint in address_endpoints {
        match probe_address_family_with_endpoint(
            client,
            address_endpoint,
            info_endpoint,
            expect_ipv6,
        )
        .await
        {
            Ok(info) => return Ok(info),
            Err(error) => errors.push(format!("{address_endpoint}: {error}")),
        }
    }

    Err(format!(
        "all {family} address lookup endpoints failed: {}",
        errors.join("; ")
    ))
}

/// Returns the resolved address and, when the metadata lookup disagreed about
/// which address it saw, the disagreement to surface next to it.
async fn probe_address_family_with_endpoint(
    client: &reqwest::Client,
    address_endpoint: &str,
    info_endpoint: Option<&str>,
    expect_ipv6: bool,
) -> Result<(PublicIpAddressInfo, Option<String>), String> {
    let response = client
        .get(address_endpoint)
        .header(USER_AGENT, "Egrio/0.1")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("address lookup failed with HTTP {status}"));
    }

    let raw_ip = response.text().await.map_err(|error| error.to_string())?;
    let ip = raw_ip
        .trim()
        .parse::<IpAddr>()
        .map_err(|error| format!("address lookup returned an invalid IP: {error}"))?;
    if ip.is_ipv6() != expect_ipv6 {
        let expected = if expect_ipv6 { "IPv6" } else { "IPv4" };
        return Err(format!("address lookup returned {ip}, expected {expected}"));
    }

    let Some(info_endpoint) = info_endpoint else {
        return Ok((
            public_ip_address_without_metadata(ip, address_endpoint),
            None,
        ));
    };
    let info_url = format!("{info_endpoint}{ip}");
    // The address is already known and trustworthy, so a metadata lookup that
    // simply fails (endpoint down, rate limited, malformed body) degrades to
    // the address alone rather than failing the whole probe.
    let Ok(info) = fetch_public_ip_metadata(client, &info_url).await else {
        return Ok((
            public_ip_address_without_metadata(ip, address_endpoint),
            None,
        ));
    };
    // A mismatch is a different signal than a failed lookup: the two probes
    // reached the internet through different egresses (per-request load
    // balancing, an injecting middlebox). Rendering that as a plain
    // no-metadata result would hide a real disagreement about where traffic
    // exits, so the address is kept and the disagreement reported alongside
    // it.
    match public_ip_info_from_response(info, ip, &info_url) {
        Ok(info) => Ok((info, None)),
        Err(mismatch) => Ok((
            public_ip_address_without_metadata(ip, address_endpoint),
            Some(mismatch),
        )),
    }
}

async fn fetch_public_ip_metadata(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<IpWhoIsResponse, String> {
    let response = client
        .get(endpoint)
        .header(USER_AGENT, "Egrio/0.1")
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("IP metadata lookup failed with HTTP {status}"));
    }
    response
        .json::<IpWhoIsResponse>()
        .await
        .map_err(|error| error.to_string())
}

fn public_ip_address_without_metadata(ip: IpAddr, source: &str) -> PublicIpAddressInfo {
    PublicIpAddressInfo {
        ip: ip.to_string(),
        isp: None,
        organization: None,
        asn: None,
        city: None,
        region: None,
        country: None,
        source: source.into(),
    }
}

fn public_ip_info_from_response(
    info: IpWhoIsResponse,
    expected_ip: IpAddr,
    source: &str,
) -> Result<PublicIpAddressInfo, String> {
    if info.success == Some(false) {
        return Err(info.message.unwrap_or_else(|| "IP lookup failed".into()));
    }

    let returned_ip = info
        .ip
        .ok_or_else(|| "IP lookup response is missing ip".to_string())?
        .parse::<IpAddr>()
        .map_err(|error| format!("IP lookup response contains an invalid ip: {error}"))?;
    if returned_ip != expected_ip {
        return Err(format!(
            "IP lookup response returned {returned_ip}, expected {expected_ip}"
        ));
    }

    let connection = info.connection.unwrap_or_default();
    Ok(PublicIpAddressInfo {
        ip: returned_ip.to_string(),
        isp: connection.isp,
        organization: connection.org,
        asn: connection.asn,
        city: info.city,
        region: info.region,
        country: info.country,
        source: source.into(),
    })
}

/// The latency of a stored profile's node, in milliseconds: one request for
/// the node's `test-url` (or `egrio_core::DEFAULT_PROBE_TEST_URL`) through
/// it, including connection setup, counted from when the node's address is
/// known (see `egrio_core`'s probe). Only a
/// node of a stored profile and the URL that profile names can be tested,
/// so the interface cannot aim it anywhere else.
pub async fn test_node_latency(
    runtime: &crate::runtime::DesktopRuntime,
    profile_id: String,
    node: String,
) -> Result<u32, String> {
    let profile = crate::profile_service::probe_profile(&profile_id)?;
    let proxy = profile
        .proxies
        .iter()
        .find(|proxy| proxy.name == node)
        .ok_or_else(|| format!("profile has no node named {node}"))?;
    if let Some(issue) = egrio_core::proxy_support_issue(&profile, proxy) {
        return Err(issue);
    }
    let test_url = proxy
        .test_url()
        .unwrap_or(egrio_core::DEFAULT_PROBE_TEST_URL)
        .to_owned();
    runtime.probe_node(profile, &node, &test_url).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn ip_lookup_response_maps_connection_and_location() {
        let expected_ip: IpAddr = "203.0.113.7".parse().expect("expected IP");
        let info = public_ip_info_from_response(
            IpWhoIsResponse {
                success: Some(true),
                message: None,
                ip: Some(expected_ip.to_string()),
                city: Some("Example City".into()),
                region: Some("Example Region".into()),
                country: Some("Example Country".into()),
                connection: Some(IpWhoIsConnection {
                    asn: Some(64512),
                    isp: Some("Example ISP".into()),
                    org: Some("Example Org".into()),
                }),
            },
            expected_ip,
            "https://example.test/info/203.0.113.7",
        )
        .expect("ip response should map");

        assert_eq!(info.ip, "203.0.113.7");
        assert_eq!(info.asn, Some(64512));
        assert_eq!(info.city.as_deref(), Some("Example City"));
    }

    #[test]
    fn ip_lookup_response_reports_provider_error() {
        let error = public_ip_info_from_response(
            IpWhoIsResponse {
                success: Some(false),
                message: Some("rate limited".into()),
                ip: None,
                city: None,
                region: None,
                country: None,
                connection: None,
            },
            "203.0.113.7".parse().expect("expected IP"),
            "https://example.test/info/203.0.113.7",
        )
        .expect_err("provider error should be surfaced");

        assert_eq!(error, "rate limited");
    }

    #[test]
    fn ip_lookup_response_rejects_a_different_address() {
        let error = public_ip_info_from_response(
            IpWhoIsResponse {
                success: Some(true),
                message: None,
                ip: Some("203.0.113.8".into()),
                city: None,
                region: None,
                country: None,
                connection: None,
            },
            "203.0.113.7".parse().expect("expected IP"),
            "https://example.test/info/203.0.113.7",
        )
        .expect_err("mismatched response should be rejected");

        assert!(error.contains("expected 203.0.113.7"));
    }

    #[tokio::test]
    async fn dual_stack_probe_routes_both_families_through_a_wildcard_core_listener() {
        let (listen_addr, requests, server) = spawn_mock_core_proxy(vec![
            ("http://probe.invalid/v4", 200, "198.51.100.4"),
            ("http://probe.invalid/v6", 200, "2001:db8::6"),
        ])
        .await;
        let wildcard = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, listen_addr.port()));
        let client = public_ip_client(&wildcard.to_string()).expect("probe client");

        let info = get_public_ip_info_with(
            &client,
            PublicIpProbeEndpoints {
                ipv4: &["http://probe.invalid/v4"],
                ipv6: &["http://probe.invalid/v6"],
                info: None,
            },
        )
        .await
        .expect("dual-stack probe");
        server.await.expect("mock proxy task");

        assert_eq!(
            info.ipv4.as_ref().map(|info| info.ip.as_str()),
            Some("198.51.100.4")
        );
        assert_eq!(
            info.ipv6.as_ref().map(|info| info.ip.as_str()),
            Some("2001:db8::6")
        );
        assert!(info.ipv4_error.is_none());
        assert!(info.ipv6_error.is_none());
        let requests = requests.lock().expect("request log");
        assert!(requests
            .iter()
            .any(|request| request.contains("http://probe.invalid/v4")));
        assert!(requests
            .iter()
            .any(|request| request.contains("http://probe.invalid/v6")));
    }

    #[tokio::test]
    async fn dual_stack_probe_keeps_the_available_address_family() {
        let (listen_addr, _requests, server) = spawn_mock_core_proxy(vec![
            ("http://probe.invalid/v4", 200, "198.51.100.4"),
            ("http://probe.invalid/v6", 503, "unavailable"),
        ])
        .await;
        let client = public_ip_client(&listen_addr.to_string()).expect("probe client");

        let info = get_public_ip_info_with(
            &client,
            PublicIpProbeEndpoints {
                ipv4: &["http://probe.invalid/v4"],
                ipv6: &["http://probe.invalid/v6"],
                info: None,
            },
        )
        .await
        .expect("single-stack fallback");
        server.await.expect("mock proxy task");

        assert_eq!(
            info.ipv4.as_ref().map(|info| info.ip.as_str()),
            Some("198.51.100.4")
        );
        assert!(info.ipv6.is_none());
        assert!(info.ipv4_error.is_none());
        assert!(info.ipv6_error.as_deref().is_some_and(|error| {
            error.contains("http://probe.invalid/v6") && error.contains("HTTP 503")
        }));
    }

    #[tokio::test]
    async fn address_family_probe_uses_the_next_endpoint_after_failure() {
        let (listen_addr, requests, server) = spawn_mock_core_proxy(vec![
            ("http://probe.invalid/v4-primary", 503, "unavailable"),
            ("http://probe.invalid/v6", 200, "2001:db8::6"),
            ("http://probe.invalid/v4-fallback", 200, "198.51.100.4"),
        ])
        .await;
        let client = public_ip_client(&listen_addr.to_string()).expect("probe client");

        let info = get_public_ip_info_with(
            &client,
            PublicIpProbeEndpoints {
                ipv4: &[
                    "http://probe.invalid/v4-primary",
                    "http://probe.invalid/v4-fallback",
                ],
                ipv6: &["http://probe.invalid/v6"],
                info: None,
            },
        )
        .await
        .expect("fallback endpoint should recover IPv4");
        server.await.expect("mock proxy task");

        assert_eq!(
            info.ipv4.as_ref().map(|info| info.ip.as_str()),
            Some("198.51.100.4")
        );
        assert!(info.ipv4_error.is_none());
        let requests = requests.lock().expect("request log");
        assert!(requests
            .iter()
            .any(|request| request.contains("http://probe.invalid/v4-primary")));
        assert!(requests
            .iter()
            .any(|request| request.contains("http://probe.invalid/v4-fallback")));
    }

    #[tokio::test]
    async fn address_survives_metadata_lookup_failure() {
        let (listen_addr, _requests, server) = spawn_mock_core_proxy(vec![
            ("http://probe.invalid/v4", 200, "198.51.100.4"),
            ("http://probe.invalid/v6", 503, "v6 unavailable"),
            (
                "http://probe.invalid/info/198.51.100.4",
                503,
                "metadata unavailable",
            ),
        ])
        .await;
        let client = public_ip_client(&listen_addr.to_string()).expect("probe client");

        let info = get_public_ip_info_with(
            &client,
            PublicIpProbeEndpoints {
                ipv4: &["http://probe.invalid/v4"],
                ipv6: &["http://probe.invalid/v6"],
                info: Some("http://probe.invalid/info/"),
            },
        )
        .await
        .expect("address should survive metadata failure");
        server.await.expect("mock proxy task");

        let ipv4 = info.ipv4.expect("IPv4 result");
        assert_eq!(ipv4.ip, "198.51.100.4");
        assert!(ipv4.isp.is_none());
        // A lookup that simply failed is not a disagreement about the egress.
        assert!(info.ipv4_error.is_none());
    }

    #[tokio::test]
    async fn a_metadata_egress_mismatch_is_reported_next_to_the_address() {
        // The address endpoint and the metadata endpoint disagree about which
        // IP they saw — the two probes reached the internet through different
        // egresses. The address is still shown, but the disagreement must not
        // be silently flattened into "no metadata".
        let (listen_addr, _requests, server) = spawn_mock_core_proxy(vec![
            ("http://probe.invalid/v4", 200, "198.51.100.4"),
            ("http://probe.invalid/v6", 503, "v6 unavailable"),
            (
                "http://probe.invalid/info/198.51.100.4",
                200,
                r#"{"ip":"203.0.113.9"}"#,
            ),
        ])
        .await;
        let client = public_ip_client(&listen_addr.to_string()).expect("probe client");

        let info = get_public_ip_info_with(
            &client,
            PublicIpProbeEndpoints {
                ipv4: &["http://probe.invalid/v4"],
                ipv6: &["http://probe.invalid/v6"],
                info: Some("http://probe.invalid/info/"),
            },
        )
        .await
        .expect("address should survive a metadata mismatch");
        server.await.expect("mock proxy task");

        let ipv4 = info.ipv4.expect("IPv4 result");
        assert_eq!(ipv4.ip, "198.51.100.4");
        assert!(ipv4.isp.is_none());
        let reported = info.ipv4_error.expect("mismatch must be reported");
        assert!(
            reported.contains("203.0.113.9") && reported.contains("198.51.100.4"),
            "mismatch should name both addresses: {reported}"
        );
    }

    #[tokio::test]
    async fn dual_stack_probe_preserves_both_family_failures() {
        let (listen_addr, _requests, server) = spawn_mock_core_proxy(vec![
            ("http://probe.invalid/v4", 503, "v4 unavailable"),
            ("http://probe.invalid/v6", 503, "v6 unavailable"),
        ])
        .await;
        let client = public_ip_client(&listen_addr.to_string()).expect("probe client");

        let info = get_public_ip_info_with(
            &client,
            PublicIpProbeEndpoints {
                ipv4: &["http://probe.invalid/v4"],
                ipv6: &["http://probe.invalid/v6"],
                info: None,
            },
        )
        .await
        .expect("family failures should remain structured");
        server.await.expect("mock proxy task");

        assert!(info.ipv4.is_none());
        assert!(info.ipv6.is_none());
        assert!(info.ipv4_error.as_deref().is_some_and(|error| {
            error.contains("IPv4") && error.contains("http://probe.invalid/v4")
        }));
        assert!(info.ipv6_error.as_deref().is_some_and(|error| {
            error.contains("IPv6") && error.contains("http://probe.invalid/v6")
        }));
    }

    #[tokio::test]
    async fn dual_stack_probe_rejects_an_address_from_the_wrong_family() {
        let (listen_addr, _requests, server) = spawn_mock_core_proxy(vec![
            ("http://probe.invalid/v4", 200, "2001:db8::4"),
            ("http://probe.invalid/v6", 503, "v6 unavailable"),
        ])
        .await;
        let client = public_ip_client(&listen_addr.to_string()).expect("probe client");

        let info = get_public_ip_info_with(
            &client,
            PublicIpProbeEndpoints {
                ipv4: &["http://probe.invalid/v4"],
                ipv6: &["http://probe.invalid/v6"],
                info: None,
            },
        )
        .await
        .expect("wrong-family response should be structured");
        server.await.expect("mock proxy task");

        assert!(info.ipv4.is_none());
        assert!(info
            .ipv4_error
            .as_deref()
            .is_some_and(|error| error.contains("expected IPv4")));
    }

    async fn spawn_mock_core_proxy(
        responses: Vec<(&'static str, u16, &'static str)>,
    ) -> (
        SocketAddr,
        Arc<Mutex<Vec<String>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind mock proxy");
        let listen_addr = listener.local_addr().expect("mock proxy address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let request_log = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            for _ in 0..responses.len() {
                let (mut stream, _) = listener.accept().await.expect("accept probe request");
                let mut buffer = vec![0_u8; 4096];
                let count = stream.read(&mut buffer).await.expect("read probe request");
                let request = String::from_utf8_lossy(&buffer[..count]);
                let request_line = request.lines().next().unwrap_or_default().to_string();
                request_log
                    .lock()
                    .expect("request log")
                    .push(request_line.clone());
                let target = request_line.split_whitespace().nth(1).unwrap_or_default();
                let (_, status, body) = responses
                    .iter()
                    .find(|(expected, _, _)| *expected == target)
                    .unwrap_or_else(|| panic!("unexpected proxy request: {request_line}"));
                let reason = if *status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write probe response");
            }
        });
        (listen_addr, requests, server)
    }
}
