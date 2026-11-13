//! The Linux package: a deb of the desktop app for x86_64 Ubuntu. It puts
//! the app and the TUN mode helper beside it in `/usr/bin`, the helper's
//! systemd unit under `/usr/lib/systemd/system`, the app's desktop entry and
//! its icons in the hicolor theme, with maintainer scripts that start the
//! helper on installation and stop it before removal (Debian Policy:
//! control fields in chapter 5, maintainer scripts in chapter 6, owners and
//! modes in 10.10). The binaries are release builds for the host, and
//! neither may need a glibc symbol version newer than the libc6 the control
//! file depends on, or the package would install where they cannot start.
//! `dpkg-deb --root-owner-group` gives every file to root.
//!
//! The package's files come from `desktop/egrio/linux/package` (the control
//! file's template, the maintainer scripts, the unit and the desktop entry)
//! and `desktop/egrio/icons`; docs/platforms/linux.md describes the layout.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use super::icons::LINUX_SIZES;
use super::{finished, host_triple, root, run};

const FILES: &str = "desktop/egrio/linux/package";
const ICONS: &str = "desktop/egrio/icons";
/// The one target the package is built for: its architecture is amd64.
const TARGET: &str = "x86_64-unknown-linux-gnu";
/// The app's GApplication ID (`APPLICATION_ID` in desktop/egrio's
/// `linux/mod.rs`), which names the desktop entry and the icon: GTK gives
/// the app's windows this ID (the Wayland app ID, X11's
/// `_GTK_APPLICATION_ID`) and GNOME Shell shows them under the desktop entry
/// of the same name.
const APP_ID: &str = "com.xinvexo.egrio";
/// The helper's unit, which goes to `LINUX_PACKAGE_UNIT_PATH` and runs the
/// helper at `LINUX_PACKAGE_SERVICE_EXECUTABLE` (egrio-platform-linux's
/// `service_layout.rs`).
const UNIT: &str = "egrio-service.service";

pub fn package(args: &[String]) -> Result<(), String> {
    if let Some(option) = args.first() {
        return Err(format!(
            "the Linux package takes no options, not {option}\n{}",
            super::usage()
        ));
    }
    let host = host_triple()?;
    if host != TARGET {
        return Err(format!("the deb is built on {TARGET}, not on {host}"));
    }
    let root = root();
    let template = read(&root.join(FILES).join("deb-control"))?;
    let glibc = glibc_floor(&template)?;
    let target_dir = root.join("target");
    build(&root, &target_dir)?;
    let release = target_dir.join("release");
    for binary in ["egrio", "egrio-service"] {
        check_glibc(&release.join(binary), &glibc)?;
    }
    let name = format!("egrio_{}_amd64", env!("CARGO_PKG_VERSION"));
    let directory = release.join("bundle/deb");
    let staging = directory.join(&name);
    assemble(&root, &release, &staging)?;
    set_directory_modes(&staging)?;
    write_control(&template, &staging)?;
    run(Command::new(staging.join("usr/bin/egrio-service")).arg("version"))?;
    let deb = directory.join(format!("{name}.deb"));
    run(Command::new("dpkg-deb")
        .args(["--root-owner-group", "--build"])
        .arg(&staging)
        .arg(&deb))?;
    std::fs::remove_dir_all(&staging).map_err(|error| format!("{}: {error}", staging.display()))?;
    println!("{}", deb.display());
    Ok(())
}

/// The app and the helper as release builds for the host, in `target_dir`.
fn build(root: &Path, target_dir: &Path) -> Result<(), String> {
    // The cargo running this task.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    run(Command::new(cargo)
        .current_dir(root)
        .args(["build", "--release", "--target-dir"])
        .arg(target_dir)
        .args(["--package", "egrio", "--package", "egrio-service"]))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

/// A dotted version's numbers, such as `[2, 39]` for 2.39.
fn numbers(version: &str) -> Option<Vec<u32>> {
    version.split('.').map(|part| part.parse().ok()).collect()
}

/// The oldest glibc the control file's dependency on libc6 accepts.
fn glibc_floor(template: &str) -> Result<Vec<u32>, String> {
    let declared = template
        .split_once("libc6 (>= ")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(version, _)| version)
        .ok_or("the deb's control file declares no libc6 (>= <version>)")?;
    numbers(declared).ok_or_else(|| format!("libc6 (>= {declared}) names no glibc version"))
}

/// Fails when `binary` needs a glibc symbol version newer than `floor`,
/// naming the symbols that do (`objdump -T` lists each dynamic symbol with
/// the version it needs).
fn check_glibc(binary: &Path, floor: &[u32]) -> Result<(), String> {
    let symbols = finished(Command::new("objdump").arg("-T").arg(binary))?;
    let newer: Vec<String> = String::from_utf8_lossy(&symbols.stdout)
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once("GLIBC_")?;
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            let needed = numbers(&version)?;
            let symbol = line.split_whitespace().last()?;
            (needed.as_slice() > floor).then(|| format!("{symbol} (GLIBC_{version})"))
        })
        .collect();
    if newer.is_empty() {
        return Ok(());
    }
    let floor: Vec<String> = floor.iter().map(u32::to_string).collect();
    Err(format!(
        "{} needs glibc symbols newer than the package's libc6 (>= {}): {}; build it against \
         that glibc",
        binary.display(),
        floor.join("."),
        newer.join(", ")
    ))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Copies `from` to `to` with `mode`, making the directories on the way.
fn install(from: &Path, to: &Path, mode: u32) -> Result<(), String> {
    let parent = to.parent().expect("an installed file has a directory");
    std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    std::fs::copy(from, to)
        .map_err(|error| format!("copy {} to {}: {error}", from.display(), to.display()))?;
    set_mode(to, mode)
}

/// The package's files under `staging` as they go under `/`, and the
/// maintainer scripts in `DEBIAN`.
fn assemble(root: &Path, release: &Path, staging: &Path) -> Result<(), String> {
    if staging.exists() {
        std::fs::remove_dir_all(staging)
            .map_err(|error| format!("{}: {error}", staging.display()))?;
    }
    let files = root.join(FILES);
    for binary in ["egrio", "egrio-service"] {
        install(
            &release.join(binary),
            &staging.join("usr/bin").join(binary),
            0o755,
        )?;
    }
    install(
        &root.join("LICENSE"),
        &staging.join("usr/share/doc/egrio/copyright"),
        0o644,
    )?;
    install(
        &files.join(UNIT),
        &staging.join("usr/lib/systemd/system").join(UNIT),
        0o644,
    )?;
    let entry = format!("{APP_ID}.desktop");
    install(
        &files.join(&entry),
        &staging.join("usr/share/applications").join(&entry),
        0o644,
    )?;
    for size in LINUX_SIZES {
        install(
            &root.join(ICONS).join(format!("{size}x{size}.png")),
            &staging.join(format!(
                "usr/share/icons/hicolor/{size}x{size}/apps/{APP_ID}.png"
            )),
            0o644,
        )?;
    }
    for script in ["postinst", "prerm", "postrm"] {
        install(
            &files.join(format!("deb-{script}")),
            &staging.join("DEBIAN").join(script),
            0o755,
        )?;
    }
    Ok(())
}

/// Every directory of the tree 0755, whatever the umask made it.
fn set_directory_modes(path: &Path) -> Result<(), String> {
    set_mode(path, 0o755)?;
    for entry in std::fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            set_directory_modes(&entry.path())?;
        }
    }
    Ok(())
}

/// `DEBIAN/control`: the template with the version and the size of what the
/// package holds.
fn write_control(template: &str, staging: &Path) -> Result<(), String> {
    let control = template
        .replace("@VERSION@", env!("CARGO_PKG_VERSION"))
        .replace("@INSTALLED_SIZE@", &installed_size(staging)?.to_string());
    let path = staging.join("DEBIAN/control");
    std::fs::write(&path, control).map_err(|error| format!("{}: {error}", path.display()))?;
    set_mode(&path, 0o644)
}

/// Installed-Size: each file's size in KiB, rounded up, and 1 KiB for each
/// directory (Debian Policy 5.6.20).
fn installed_size(path: &Path) -> Result<u64, String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.is_dir() {
        return Ok(metadata.len().div_ceil(1024));
    }
    let mut size = 1;
    for entry in std::fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
        size += installed_size(&entry.path())?;
    }
    Ok(size)
}
