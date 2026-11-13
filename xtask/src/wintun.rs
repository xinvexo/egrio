//! Wintun, the driver library the privileged service loads for TUN mode on
//! Windows: the official signed build of a pinned release
//! (<https://www.wintun.net/>), checked by SHA-256 and unpacked under
//! `target/wintun/<version>`. The project allows redistributing the DLL
//! exactly as downloaded, so it keeps its name.

use std::path::{Path, PathBuf};

use super::{pinned, root};

const VERSION: &str = "0.14.1";
/// The SHA-256 of `wintun-0.14.1.zip` as wintun.net publishes it.
const SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

/// Unpacks the release and returns where it is.
pub fn prepare() -> Result<PathBuf, String> {
    let unpacked = root().join("target").join("wintun").join(VERSION);
    pinned::unpack(
        &format!("https://www.wintun.net/builds/wintun-{VERSION}.zip"),
        SHA256,
        &unpacked,
    )?;
    Ok(unpacked)
}

/// The DLL for a Windows architecture (`win-x64` and the like).
pub fn library(unpacked: &Path, architecture: &str) -> Result<PathBuf, String> {
    let directory = match architecture {
        "win-x64" => "amd64",
        "win-arm64" => "arm64",
        "win-x86" => "x86",
        other => return Err(format!("no Wintun build for {other}")),
    };
    Ok(unpacked
        .join("wintun/bin")
        .join(directory)
        .join("wintun.dll"))
}
