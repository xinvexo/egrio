//! Egrio's own updates. Releases are published on GitHub, tagged
//! `v<version>`, each with one installer per platform and a `SHA256SUMS`
//! list (`.github/workflows/release.yml`, docs/runbooks/release.md). The
//! newest release is read from GitHub's REST API
//! (`GET /repos/{owner}/{repo}/releases/latest`, which leaves drafts and
//! prereleases out) and compared with this build's version; this platform's
//! installer is downloaded into the data directory and checked against the
//! list before the system opens it.

use std::path::PathBuf;

use reqwest::header::{ACCEPT, USER_AGENT};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::remote_fetch::{
    read_limited_body, read_limited_bytes, remote_fetch_client, remote_file_client, request_error,
    validate_remote_url,
};

/// The repository whose releases are Egrio's: the one the release workflow
/// publishes to, which a build names in `EGRIO_RELEASES_REPOSITORY`.
const RELEASES: &str = match option_env!("EGRIO_RELEASES_REPOSITORY") {
    Some(repository) => repository,
    None => "xinvexo/egrio",
};
const CHECKSUMS: &str = "SHA256SUMS";
/// Larger than any installer has grown to, with room to grow.
const MAX_INSTALLER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CHECKSUMS_BYTES: u64 = 64 * 1024;

/// The installer replaces the running app, which it cannot while the app
/// runs: macOS does not replace a running app bundle and Windows a running
/// executable, so the app quits once the system has the installer. A Linux
/// package manager replaces a running program's files.
pub const INSTALLER_REPLACES_APP: bool = cfg!(any(target_os = "macos", windows));

/// A release newer than this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// Its version, without the tag's `v`.
    pub version: String,
    /// Its page on GitHub.
    pub page: String,
    /// This platform's installer, when the release carries one.
    pub installer: Option<Asset>,
    checksums: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub name: String,
    url: String,
}

#[derive(Deserialize)]
struct ReleaseJson {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<AssetJson>,
}

#[derive(Deserialize)]
struct AssetJson {
    name: String,
    browser_download_url: String,
}

/// The newest release when it is newer than this build; none when it is
/// not, or when nothing has been published yet.
pub async fn newer_release() -> Result<Option<Release>, String> {
    let release = latest_release().await?;
    Ok(release.filter(|release| newer(&release.version, env!("CARGO_PKG_VERSION"))))
}

async fn latest_release() -> Result<Option<Release>, String> {
    #[cfg(debug_assertions)]
    if let Some(feed) = std::env::var_os("EGRIO_UPDATE_FEED") {
        let body = std::fs::read_to_string(&feed)
            .map_err(|error| format!("{}: {error}", PathBuf::from(&feed).display()))?;
        return parse(&body).map(Some);
    }
    let response = remote_fetch_client()?
        .get(format!(
            "https://api.github.com/repos/{RELEASES}/releases/latest"
        ))
        .header(USER_AGENT, user_agent())
        .header(ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .map_err(request_error)?;
    // A repository without a published release answers 404.
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(format!(
            "GitHub answered HTTP {}",
            response.status().as_u16()
        ));
    }
    parse(&read_limited_body(response).await?).map(Some)
}

fn parse(body: &str) -> Result<Release, String> {
    let json: ReleaseJson = serde_json::from_str(body)
        .map_err(|error| format!("the release's description is unreadable: {error}"))?;
    let version = json.tag_name.trim().trim_start_matches('v').to_string();
    let asset = |name: &str| json.assets.iter().find(|asset| asset.name == name);
    let installer = installer_name(&version)
        .as_deref()
        .and_then(asset)
        .map(|asset| Asset {
            name: asset.name.clone(),
            url: asset.browser_download_url.clone(),
        });
    let checksums = asset(CHECKSUMS).map(|asset| asset.browser_download_url.clone());
    Ok(Release {
        version,
        page: json.html_url,
        installer,
        checksums,
    })
}

/// Whether `candidate` is newer than `current`, by major, minor and patch.
fn newer(candidate: &str, current: &str) -> bool {
    match (numbers(candidate), numbers(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

fn numbers(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.split(['-', '+']).next()?;
    let mut parts = core.split('.').map(str::parse::<u64>);
    let numbers = (
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    );
    parts.next().is_none().then_some(numbers)
}

/// This platform's installer as a release names it: the disk image for this
/// Mac's architecture, the Windows setup program, the Debian package on a
/// Debian-based Linux. Other systems get none and are pointed at the page.
fn installer_name(version: &str) -> Option<String> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some(format!("Egrio_{version}_aarch64.dmg"))
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some(format!("Egrio_{version}_x64.dmg"))
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Some(format!("Egrio_{version}_x64-setup.exe"))
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) && debian_like() {
        Some(format!("egrio_{version}_amd64.deb"))
    } else {
        None
    }
}

/// Whether os-release(5) names Debian or a system based on it.
fn debian_like() -> bool {
    std::fs::read_to_string("/etc/os-release").is_ok_and(|release| {
        release.lines().any(|line| {
            line.split_once('=').is_some_and(|(key, value)| {
                (key == "ID" || key == "ID_LIKE")
                    && value
                        .trim_matches('"')
                        .split_whitespace()
                        .any(|id| id == "debian" || id == "ubuntu")
            })
        })
    })
}

/// Downloads the release's installer for this platform into the data
/// directory, checks it against the release's SHA-256 list, and returns
/// where it is. Only the newest download stays.
pub async fn download_installer(release: &Release) -> Result<PathBuf, String> {
    let installer = release
        .installer
        .as_ref()
        .ok_or("this release has no installer for this system")?;
    let checksums = release
        .checksums
        .as_ref()
        .ok_or("this release lists no SHA-256 checksums")?;
    let client = remote_file_client()?;
    let list = download(&client, checksums, MAX_CHECKSUMS_BYTES).await?;
    let expected = expected_sha256(&String::from_utf8_lossy(&list), &installer.name)
        .ok_or_else(|| format!("{CHECKSUMS} lists no {}", installer.name))?;
    let bytes = download(&client, &installer.url, MAX_INSTALLER_BYTES).await?;
    if hex(&Sha256::digest(&bytes)) != expected {
        return Err(format!("{} does not match its SHA-256", installer.name));
    }
    let directory = crate::app_paths::app_data_dir()?.join("updates");
    if directory.exists() {
        std::fs::remove_dir_all(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
    }
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let path = directory.join(&installer.name);
    std::fs::write(&path, &bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

async fn download(client: &reqwest::Client, url: &str, limit: u64) -> Result<Vec<u8>, String> {
    #[cfg(debug_assertions)]
    if let Some(path) = url.strip_prefix("file://") {
        return std::fs::read(path).map_err(|error| format!("{path}: {error}"));
    }
    let response = client
        .get(validate_remote_url(url)?)
        .header(USER_AGENT, user_agent())
        .send()
        .await
        .map_err(request_error)?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    read_limited_bytes(response, limit).await
}

/// The SHA-256 a `sha256sum`-style list gives `name`.
fn expected_sha256(list: &str, name: &str) -> Option<String> {
    list.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let hash = fields.next()?;
        let file = fields.next()?.trim_start_matches('*');
        (file == name && hash.len() == 64).then(|| hash.to_ascii_lowercase())
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn user_agent() -> String {
    format!("Egrio/{}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_release_is_newer_by_major_minor_and_patch() {
        assert!(newer("0.2.0", "0.1.9"));
        assert!(newer("1.0.0", "0.9.9"));
        assert!(newer("0.1.10", "0.1.9"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.0.9", "0.1.0"));
        assert!(!newer("garbage", "0.1.0"));
        assert!(!newer("0.2", "0.1.0"), "a version has three numbers");
        assert!(newer("0.2.0-beta", "0.1.0"), "a suffix is ignored");
    }

    #[test]
    fn a_release_names_this_platforms_installer_and_its_checksums() {
        let installer = installer_name("1.2.3");
        let assets: Vec<String> = [
            "Egrio_1.2.3_aarch64.dmg",
            "Egrio_1.2.3_x64.dmg",
            "Egrio_1.2.3_x64-setup.exe",
            "egrio_1.2.3_amd64.deb",
            "SHA256SUMS",
        ]
        .iter()
        .map(|name| {
            format!(r#"{{"name":"{name}","browser_download_url":"https://example.com/{name}"}}"#)
        })
        .collect();
        let body = format!(
            r#"{{"tag_name":"v1.2.3","html_url":"https://github.com/xinvexo/egrio/releases/tag/v1.2.3","assets":[{}]}}"#,
            assets.join(",")
        );
        let release = parse(&body).unwrap();
        assert_eq!(release.version, "1.2.3");
        assert_eq!(
            release.installer.as_ref().map(|asset| asset.name.clone()),
            installer
        );
        assert_eq!(
            release.checksums.as_deref(),
            Some("https://example.com/SHA256SUMS")
        );
    }

    #[test]
    fn the_checksum_list_gives_each_file_its_hash() {
        let hash = "a".repeat(64);
        let list = format!(
            "{hash}  Egrio_1.2.3_x64.dmg\n{}  *egrio_1.2.3_amd64.deb\n",
            "B".repeat(64)
        );
        assert_eq!(expected_sha256(&list, "Egrio_1.2.3_x64.dmg"), Some(hash));
        assert_eq!(
            expected_sha256(&list, "egrio_1.2.3_amd64.deb"),
            Some("b".repeat(64))
        );
        assert_eq!(expected_sha256(&list, "missing"), None);
    }
}
