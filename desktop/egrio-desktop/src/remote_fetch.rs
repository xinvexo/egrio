//! Downloads of remote documents: a profile imported from a URL, once, the
//! rule sets its rule-providers name, and the GEODATA files. Hardened
//! clients for all of them: bounded time, size and redirects, and no hop
//! into the host or its LAN.
use super::profile_store::{ProfileStore, SavedProfileSummary};
use reqwest::header::USER_AGENT;
use reqwest::redirect::Policy;
use reqwest::Url;
use std::time::Duration;

/// Identifies Egrio and requests the supported Clash YAML dialect from
/// subscription services. The `(clash.meta)` compatibility marker selects
/// a configuration response rather than a list of share links.
const PROFILE_USER_AGENT: &str = concat!("Egrio/", env!("CARGO_PKG_VERSION"), " (clash.meta)");

const REMOTE_FETCH_TIMEOUT_SECONDS: u64 = 20;
const REMOTE_MAX_REDIRECTS: usize = 5;
const MAX_REMOTE_DOCUMENT_BYTES: u64 = 32 * 1024 * 1024;
/// A large file may take minutes on a slow link; one that stops arriving
/// for this long has stalled.
const REMOTE_FILE_IDLE_SECONDS: u64 = 30;
const REMOTE_FILE_TIMEOUT_SECONDS: u64 = 15 * 60;

/// Downloads the document at `url` once and saves it as a new profile. The
/// profile keeps no link to the URL: importing again is how it gets newer
/// content.
pub async fn import_remote_profile(
    name: String,
    url: String,
) -> Result<SavedProfileSummary, String> {
    let url = validate_remote_url(&url)?;
    let response = remote_fetch_client()?
        .get(url)
        .header(USER_AGENT, PROFILE_USER_AGENT)
        .send()
        .await
        .map_err(request_error)?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!("profile download failed: HTTP {}", status.as_u16()));
    }
    let body = read_limited_body(response).await?;
    if is_share_link_list(&body) {
        return Err(
            "the URL answered with a list of share links, not a Clash configuration; \
             use the provider's Clash subscription link"
                .into(),
        );
    }
    let _notify = crate::events::notify_profiles_on_return();
    ProfileStore::open()
        .and_then(|store| store.import_profile(name, body))
        .map_err(|error| error.to_string())
}

/// Whether a download is what a subscription service sends a client it does
/// not take for a Clash one: share links (`ss://`, `trojan://`, ...) one a
/// line, or the base64 of such a list, which is one unbroken run of the
/// base64 alphabet. A Clash configuration is a YAML mapping, whose first
/// key ends in a colon.
fn is_share_link_list(body: &str) -> bool {
    let text = body.trim();
    if text.is_empty() {
        return false;
    }
    let is_link = |line: &str| {
        line.split_once("://").is_some_and(|(scheme, rest)| {
            !rest.is_empty()
                && !scheme.is_empty()
                && scheme
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    };
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    if lines.clone().all(is_link) {
        return true;
    }
    lines.all(|line| {
        line.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
    }) && text.len() >= 16
}

/// A failed request with its causes (DNS, connect, TLS, timeout) but without
/// the URL, whose query often carries an access token.
pub(crate) fn request_error(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut message = error.to_string();
    let mut cause = std::error::Error::source(&error);
    while let Some(error) = cause {
        message.push_str(": ");
        message.push_str(&error.to_string());
        cause = error.source();
    }
    message
}

pub(crate) fn remote_fetch_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(REMOTE_FETCH_TIMEOUT_SECONDS))
        .redirect(host_checked_redirect_policy())
        .build()
        .map_err(|error| format!("failed to build the download HTTP client: {error}"))
}

/// For files of many megabytes: bounded by a stall rather than a short
/// total, which a slow link would exceed.
pub(crate) fn remote_file_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(REMOTE_FETCH_TIMEOUT_SECONDS))
        .read_timeout(Duration::from_secs(REMOTE_FILE_IDLE_SECONDS))
        .timeout(Duration::from_secs(REMOTE_FILE_TIMEOUT_SECONDS))
        .redirect(host_checked_redirect_policy())
        .build()
        .map_err(|error| format!("failed to build the download HTTP client: {error}"))
}

/// Bounds redirects by count *and* destination. A remote URL that 302s to
/// `127.0.0.1` or `169.254.169.254` would otherwise reach host-local services
/// the initial-URL check was meant to keep it away from, since a count-only
/// policy never re-examines where a hop lands.
fn host_checked_redirect_policy() -> Policy {
    Policy::custom(|attempt| {
        if attempt.previous().len() >= REMOTE_MAX_REDIRECTS {
            return attempt.error(format!(
                "URL redirected more than {REMOTE_MAX_REDIRECTS} times"
            ));
        }
        match validate_remote_url(attempt.url().as_str()) {
            Ok(_) => attempt.follow(),
            Err(error) => attempt.error(error),
        }
    })
}

pub(crate) fn validate_remote_url(raw_url: &str) -> Result<Url, String> {
    let url = Url::parse(raw_url.trim()).map_err(|error| format!("invalid URL: {error}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "unsupported URL scheme '{scheme}'; only http and https are allowed"
            ))
        }
    }
    let Some(host) = url.host_str() else {
        return Err("URL must include a host".into());
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not contain embedded credentials".into());
    }
    // A literal host-local address is refused outright. Names are left to DNS
    // — resolving here then dialing separately would only move the race, and
    // the fetch returns no body to the caller, so a name that resolves inward
    // is a far weaker oracle than a URL that names the target directly.
    //
    // `host_str` renders IPv6 literals bracketed and no `IpAddr` parse accepts
    // those, so the brackets come off first; otherwise every v6 address would
    // silently pass the check.
    let literal = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(address) = literal.parse::<std::net::IpAddr>() {
        if egrio_core::is_forbidden_direct_destination(address) {
            return Err(format!(
                "URL must not point at the host or its LAN ({address})"
            ));
        }
    }

    Ok(url)
}

pub(crate) async fn read_limited_body(response: reqwest::Response) -> Result<String, String> {
    let body = read_limited_bytes(response, MAX_REMOTE_DOCUMENT_BYTES).await?;
    String::from_utf8(body).map_err(|error| format!("download is not UTF-8: {error}"))
}

pub(crate) async fn read_limited_bytes(
    mut response: reqwest::Response,
    limit: u64,
) -> Result<Vec<u8>, String> {
    if let Some(content_length) = response.content_length() {
        ensure_body_size_within_limit(content_length, limit)?;
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(request_error)? {
        let next_len = body.len() as u64 + chunk.len() as u64;
        ensure_body_size_within_limit(next_len, limit)?;
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn ensure_body_size_within_limit(size: u64, limit: u64) -> Result<(), String> {
    if size > limit {
        Err(format!("download exceeds the {limit} byte limit"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The download names Egrio and the dialect it reads, the flag a
    /// subscription panel looks for before it sends a Clash configuration.
    #[test]
    fn a_profile_download_names_the_dialect_it_reads() {
        assert_eq!(
            PROFILE_USER_AGENT,
            format!("Egrio/{} (clash.meta)", env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn an_answer_of_share_links_is_told_from_a_configuration() {
        // The base64 fixtures contain only example.com share links with the
        // literal sample password "password", including nested SIP002 userinfo.
        for links in [
            "c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2Y0dGemMzZHZjbVJBWlhoaGJYQnNaUzVqYjIwNk9ETTRPQT09I0hLCg==",
            "c3M6Ly9ZV1Z6TFRJMU5pMW5ZMjA2Y0dGemMzZHZjbVJBWlhoaGJYQnNaUzVqYjIwNk9ETTRPQT09I0hL\r\ndHJvamFuOi8vcGFzc3dvcmRAZXhhbXBsZS5jb206NDQzI1VT\n",
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388#HK\ntrojan://password@example.com:443#US\n",
            "  hysteria2://password@example.com:443?sni=example.com#JP  ",
        ] {
            assert!(is_share_link_list(links), "{links}");
        }
        for configuration in [
            "",
            "proxies: []\n",
            "mixed-port: 7890\nmode: Rule\nproxies:\n  - {name: A, type: ss}\n",
            "# a comment\nproxies: ~\n",
            "{proxies: []}",
            "short",
        ] {
            assert!(!is_share_link_list(configuration), "{configuration}");
        }
    }

    #[test]
    fn url_validation_allows_http_and_https_only() {
        assert!(validate_remote_url("https://example.com/sub.yaml").is_ok());
        assert!(validate_remote_url("http://example.com/sub.yaml").is_ok());

        let file_error =
            validate_remote_url("file:///tmp/sub.yaml").expect_err("file scheme must be rejected");
        assert!(file_error.contains("only http and https"));

        let credential_error = validate_remote_url("https://user:secret@example.com/sub.yaml")
            .expect_err("embedded credentials must be rejected");
        assert!(credential_error.contains("embedded credentials"));
    }

    #[test]
    fn url_validation_refuses_host_local_addresses() {
        for inward in [
            "http://127.0.0.1/sub.yaml",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1/sub.yaml",
            "http://10.0.0.5/sub.yaml",
            "http://[::1]/sub.yaml",
            // IPv4-mapped IPv6 must not slip loopback past the v6 arm.
            "http://[::ffff:127.0.0.1]/sub.yaml",
        ] {
            let error =
                validate_remote_url(inward).expect_err(&format!("{inward} must be rejected"));
            assert!(
                error.contains("host or its LAN"),
                "unexpected rejection for {inward}: {error}"
            );
        }

        // Public literals and names still fetch.
        assert!(validate_remote_url("http://93.184.216.34/sub.yaml").is_ok());
        assert!(validate_remote_url("https://example.com/sub.yaml").is_ok());
    }

    #[test]
    fn body_size_limit_rejects_oversized_responses() {
        assert!(ensure_body_size_within_limit(
            MAX_REMOTE_DOCUMENT_BYTES,
            MAX_REMOTE_DOCUMENT_BYTES
        )
        .is_ok());

        let error =
            ensure_body_size_within_limit(MAX_REMOTE_DOCUMENT_BYTES + 1, MAX_REMOTE_DOCUMENT_BYTES)
                .expect_err("an oversized download is rejected");
        assert!(error.contains("exceeds"));
    }

    #[tokio::test]
    async fn response_reader_accepts_small_http_body() {
        let url =
            serve_http_response("HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\nproxies: []\nrules:")
                .await;
        let response = hermetic_test_client()
            .get(url)
            .send()
            .await
            .expect("test response");

        let body = read_limited_body(response)
            .await
            .expect("small response is accepted");

        assert_eq!(body, "proxies: []\nrules:");
    }

    #[tokio::test]
    async fn response_reader_rejects_oversized_content_length() {
        let url = serve_http_response(&format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_REMOTE_DOCUMENT_BYTES + 1
        ))
        .await;
        let response = hermetic_test_client()
            .get(url)
            .send()
            .await
            .expect("test response");

        let error = read_limited_body(response)
            .await
            .expect_err("oversized response is rejected");

        assert!(error.contains("exceeds"));
    }

    #[tokio::test]
    async fn a_refused_request_names_its_cause_but_not_the_url() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("listener local addr");
        drop(listener);
        let error = hermetic_test_client()
            .get(format!("http://{addr}/sub?token=secret"))
            .send()
            .await
            .expect_err("nothing listens on the port");

        let message = request_error(error);

        assert!(message.starts_with("error sending request: "), "{message}");
        assert!(!message.contains("secret"), "{message}");
    }

    #[tokio::test]
    async fn a_truncated_body_names_its_cause() {
        let url =
            serve_http_response("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nproxies:").await;
        let response = hermetic_test_client()
            .get(url)
            .send()
            .await
            .expect("test response");

        let error = read_limited_body(response)
            .await
            .expect_err("the body ends early");

        assert!(
            error.starts_with("error decoding response body: "),
            "{error}"
        );
    }

    /// A client that ignores the host's proxy configuration, so loopback
    /// requests stay inside the test even when a system proxy is enabled.
    fn hermetic_test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .expect("test HTTP client")
    }

    async fn serve_http_response(response: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test HTTP listener");
        let addr = listener.local_addr().expect("listener local addr");
        let response = response.as_bytes().to_vec();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test HTTP request");
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await;
            stream
                .write_all(&response)
                .await
                .expect("write test HTTP response");
        });
        format!("http://{addr}/profile.yaml")
    }
}
