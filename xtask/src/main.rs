//! The repository's tasks, run as `cargo xtask <task>`:
//!
//! - `check [--full]` runs the repository's gates: the static gate every
//!   commit passes, and with `--full` every test suite too.
//! - `docs` checks the documentation rules a machine can check.
//! - `bench-compare <baseline.json> <candidate.json>` compares two runs of a
//!   Core throughput benchmark on the same host.
//! - `package [--target <triple>] [--identity <name>] [--notarize <profile>]`
//!   builds the desktop app's package for this machine's platform. On macOS
//!   that is the signed `Egrio.app` and a signed DMG, both notarized and
//!   stapled when `--notarize` names a keychain profile of `xcrun notarytool`.
//!   `--test-control` builds an acceptance app instead: signed the same way,
//!   with the test control socket, and never notarized or put in a DMG. On
//!   Windows it is the NSIS installer, which takes only `--target`; on x86_64
//!   Linux it is the Ubuntu deb, which takes no options.
//! - `icons` renders the icon artwork in `design/icons` into the icons the
//!   desktop app carries.
//! - `windows-deps [--bindings] [--target <triple>]` fetches the pinned
//!   Windows App SDK and Wintun and stages the DLLs the Windows builds load
//!   beside them; `--bindings` also regenerates the WinUI bindings.

mod bench;
mod check;
mod contracts;
mod dependencies;
mod docs;
mod icons;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod pinned;
#[cfg(windows)]
mod windows;
mod windows_app_sdk;
mod windows_deps;
mod wintun;

use std::path::PathBuf;
use std::process::{Command, ExitCode, Output};

fn usage() -> &'static str {
    "usage: cargo xtask check [--full]
       cargo xtask docs
       cargo xtask bench-compare <baseline.json> <candidate.json>
       cargo xtask package [--target <triple>] [--identity <name>] [--notarize <keychain-profile> | --test-control]
       cargo xtask icons
       cargo xtask windows-deps [--bindings] [--target <triple>]"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some((task, rest)) = args.split_first() {
        if task == "bench-compare" {
            return bench::run(rest);
        }
    }
    let result = match args.split_first() {
        Some((task, rest)) if task == "check" => check::gate(&root(), rest),
        Some((task, rest)) if task == "docs" && rest.is_empty() => docs::run(&root()),
        Some((task, rest)) if task == "package" => package(rest),
        Some((task, rest)) if task == "icons" && rest.is_empty() => icons::generate(),
        Some((task, rest)) if task == "windows-deps" => {
            windows_deps::Options::parse(rest).and_then(windows_deps::prepare)
        }
        _ => Err(usage().into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(target_os = "macos")]
fn package(args: &[String]) -> Result<(), String> {
    macos::package(macos::Options::parse(args)?)
}

#[cfg(windows)]
fn package(args: &[String]) -> Result<(), String> {
    windows::package(windows::Options::parse(args)?)
}

#[cfg(target_os = "linux")]
fn package(args: &[String]) -> Result<(), String> {
    linux::package(args)
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
fn package(_args: &[String]) -> Result<(), String> {
    Err("the package is built on macOS, Windows and Linux".into())
}

/// The workspace's root, which the tasks run in.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the workspace")
        .to_path_buf()
}

/// The Rust host this runs on, such as `aarch64-apple-darwin`.
fn host_triple() -> Result<String, String> {
    let info = finished(Command::new("rustc").arg("-vV"))?;
    String::from_utf8_lossy(&info.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(String::from)
        .ok_or_else(|| "rustc -vV names no host".into())
}

/// What a command printed, once it succeeded.
fn finished(command: &mut Command) -> Result<Output, String> {
    let shown = format!("{command:?}");
    let result = command
        .output()
        .map_err(|error| format!("{shown}: {error}"))?;
    if result.status.success() {
        Ok(result)
    } else {
        Err(format!(
            "{shown} failed ({}): {}{}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        ))
    }
}

/// Runs `command` with its output shown, failing when it fails.
fn run(command: &mut Command) -> Result<(), String> {
    let shown = format!("{command:?}");
    eprintln!("xtask: {shown}");
    let status = command
        .status()
        .map_err(|error| format!("{shown}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{shown} failed ({status})"))
    }
}
