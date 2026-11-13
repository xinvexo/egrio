//! Archives the tasks fetch at pinned versions: downloaded with curl,
//! checked against the SHA-256 the task names, and unpacked with the
//! system's tar, whose bsdtar on macOS and Windows reads zip archives too.

use std::path::Path;
use std::process::Command;

use sha2::{Digest, Sha256};

use super::run;

/// Unpacks the archive at `url` into `into` unless an earlier run left it
/// there checked.
pub fn unpack(url: &str, sha256: &str, into: &Path) -> Result<(), String> {
    let marker = into.join(".verified");
    if std::fs::read_to_string(&marker).is_ok_and(|verified| verified == sha256) {
        return Ok(());
    }
    let parent = into
        .parent()
        .ok_or_else(|| format!("{} has no parent", into.display()))?;
    std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    let mut archive = into.as_os_str().to_owned();
    archive.push(".download");
    let archive = std::path::PathBuf::from(archive);
    run(Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&archive)
        .arg(url))?;
    let bytes =
        std::fs::read(&archive).map_err(|error| format!("{}: {error}", archive.display()))?;
    let actual = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != sha256 {
        let _ = std::fs::remove_file(&archive);
        return Err(format!("{url}: SHA-256 {actual}, expected {sha256}"));
    }
    if into.exists() {
        std::fs::remove_dir_all(into).map_err(|error| format!("{}: {error}", into.display()))?;
    }
    std::fs::create_dir_all(into).map_err(|error| format!("{}: {error}", into.display()))?;
    run(Command::new("tar")
        .arg("-xf")
        .arg(&archive)
        .arg("-C")
        .arg(into))?;
    std::fs::write(&marker, sha256).map_err(|error| format!("{}: {error}", marker.display()))?;
    let _ = std::fs::remove_file(&archive);
    Ok(())
}
