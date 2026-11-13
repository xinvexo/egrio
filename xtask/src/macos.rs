//! The macOS package: `Egrio.app` with the privileged service and its
//! launchd property list, signed with the hardened runtime, then a signed
//! disk image holding it beside a link to Applications. With a notary
//! keychain profile the app is notarized and stapled before it goes into the
//! image, and the image after it; Apple's notary service tickets the
//! submitted file and everything in it, and a ticket stapled to each lets
//! Gatekeeper pass the app offline too ("Customizing the notarization
//! workflow"; hardened runtime and secure timestamp per "Notarizing macOS
//! software before distribution").
//!
//! The bundle's files come from `desktop/egrio/macos` (the
//! Info.plist template and the service's property list) and
//! `desktop/egrio/icons`; docs/platforms/macos.md describes the
//! layout.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::{finished, host_triple, root, run};

const APP: &str = "Egrio.app";
/// The service's property list, named after its launchd label
/// (`MACOS_SERVICE_PLIST` in egrio-platform-macos's `service_layout.rs`).
const SERVICE_PLIST: &str = "com.xinvexo.egrio.service.plist";
/// What signs by default: a certificate for apps distributed outside the
/// App Store, which notarization takes.
const IDENTITY: &str = "Developer ID Application";
/// The oldest macOS the app runs on: SMAppService needs 13.
const DEPLOYMENT_TARGET: &str = "13.0";

pub struct Options {
    target: String,
    identity: String,
    notary: Option<String>,
    /// An acceptance build: the app with its test control socket, signed
    /// like a release so the service accepts it, never notarized or put in
    /// a disk image.
    test_control: bool,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self {
            target: host_triple()?,
            identity: IDENTITY.into(),
            notary: None,
            test_control: false,
        };
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            if flag == "--test-control" {
                options.test_control = true;
                continue;
            }
            let value = args
                .next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n{}", super::usage()))?;
            match flag.as_str() {
                "--target" => options.target = value,
                "--identity" => options.identity = value,
                "--notarize" => options.notary = Some(value),
                other => return Err(format!("unknown option {other}\n{}", super::usage())),
            }
        }
        if options.test_control && options.notary.is_some() {
            return Err("an acceptance build with test control is never notarized".into());
        }
        Ok(options)
    }
}

pub fn package(options: Options) -> Result<(), String> {
    let root = root();
    let target_dir = if options.test_control {
        root.join("target/test-control")
    } else {
        root.join("target")
    };
    let release = target_dir.join(&options.target).join("release");
    build(&root, &target_dir, &options.target, options.test_control)?;
    let app = release.join("bundle/macos").join(APP);
    assemble(&root, &release, &app)?;
    sign(
        &app.join("Contents/MacOS/egrio-service"),
        &options.identity,
        true,
    )?;
    sign(&app, &options.identity, true)?;
    check(&app)?;
    if options.test_control {
        println!("{}", app.display());
        return Ok(());
    }
    if let Some(profile) = &options.notary {
        let archive = release.join("bundle/macos/Egrio.zip");
        run(Command::new("ditto")
            .args(["-c", "-k", "--keepParent"])
            .arg(&app)
            .arg(&archive))?;
        notarize(&archive, profile)?;
        std::fs::remove_file(&archive).map_err(|error| error.to_string())?;
        staple(&app)?;
    }
    let image = disk_image(&release, &app, &options.target)?;
    sign(&image, &options.identity, false)?;
    run(Command::new("hdiutil").arg("verify").arg(&image))?;
    if let Some(profile) = &options.notary {
        notarize(&image, profile)?;
        staple(&image)?;
        run(Command::new("spctl")
            .args(["--assess", "--type", "execute", "-v"])
            .arg(&app))?;
    }
    println!("{}\n{}", app.display(), image.display());
    Ok(())
}

/// The app and the service, for the target, as release builds for macOS 13,
/// in `target_dir`: an acceptance build's app has test control, so it is
/// built in a directory of its own and never where a release package takes
/// its binary from.
fn build(root: &Path, target_dir: &Path, target: &str, test_control: bool) -> Result<(), String> {
    // The cargo running this task.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command
        .current_dir(root)
        .env("MACOSX_DEPLOYMENT_TARGET", DEPLOYMENT_TARGET)
        .args(["build", "--release", "--target", target, "--target-dir"])
        .arg(target_dir)
        .args(["--package", "egrio", "--package", "egrio-service"]);
    if test_control {
        command.args(["--features", "egrio/test-control"]);
    }
    run(&mut command)
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|error| format!("copy {} to {}: {error}", from.display(), to.display()))
}

fn assemble(root: &Path, release: &Path, app: &Path) -> Result<(), String> {
    let make = |path: PathBuf| {
        std::fs::create_dir_all(&path).map_err(|error| format!("{}: {error}", path.display()))
    };
    if app.exists() {
        std::fs::remove_dir_all(app).map_err(|error| format!("{}: {error}", app.display()))?;
    }
    for directory in [
        "Contents/MacOS",
        "Contents/Resources",
        "Contents/Library/LaunchDaemons",
    ] {
        make(app.join(directory))?;
    }
    let files = root.join("desktop/egrio");
    let template = files.join("macos/Info.plist");
    let info = std::fs::read_to_string(&template)
        .map_err(|error| format!("{}: {error}", template.display()))?
        .replace("@VERSION@", env!("CARGO_PKG_VERSION"));
    let info_path = app.join("Contents/Info.plist");
    std::fs::write(&info_path, info)
        .map_err(|error| format!("{}: {error}", info_path.display()))?;
    copy(&release.join("egrio"), &app.join("Contents/MacOS/egrio"))?;
    copy(
        &release.join("egrio-service"),
        &app.join("Contents/MacOS/egrio-service"),
    )?;
    copy(
        &files.join("macos").join(SERVICE_PLIST),
        &app.join("Contents/Library/LaunchDaemons")
            .join(SERVICE_PLIST),
    )?;
    copy(
        &root.join("LICENSE"),
        &app.join("Contents/Resources/LICENSE"),
    )?;
    copy(
        &files.join("icons/icon.icns"),
        &app.join("Contents/Resources/icon.icns"),
    )
}

/// Signs `path`; code takes the hardened runtime. An ad hoc signature (`-`)
/// takes no secure timestamp.
fn sign(path: &Path, identity: &str, code: bool) -> Result<(), String> {
    let mut command = Command::new("codesign");
    command.args(["--force", "--sign", identity]);
    if code {
        command.args(["--options", "runtime"]);
    }
    if identity != "-" {
        command.arg("--timestamp");
    }
    run(command.arg(path))
}

/// The team a signature names, `not set` for an ad hoc one.
fn team(path: &Path) -> Result<String, String> {
    let details = finished(Command::new("codesign").arg("-dv").arg(path))?;
    // codesign writes the details to standard error.
    String::from_utf8_lossy(&details.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))
        .map(String::from)
        .ok_or_else(|| format!("{} names no team", path.display()))
}

/// What the service needs of the bundle before anything registers it: a
/// signature that verifies, the service signed by the app's own team (it
/// accepts only such peers), a property list launchd can read, and a
/// service that runs.
fn check(app: &Path) -> Result<(), String> {
    run(Command::new("codesign")
        .args(["--verify", "--deep", "--strict", "--verbose=2"])
        .arg(app))?;
    let service = app.join("Contents/MacOS/egrio-service");
    let app_team = team(app)?;
    if app_team == "not set" {
        eprintln!("xtask: ad hoc signature: the service will accept only root as its peer");
    } else if team(&service)? != app_team {
        return Err(format!(
            "the service is not signed by the app's team {app_team}"
        ));
    }
    run(Command::new("plutil").arg("-lint").arg(
        app.join("Contents/Library/LaunchDaemons")
            .join(SERVICE_PLIST),
    ))?;
    run(Command::new(&service).arg("version"))
}

/// The disk image: the app beside a link to Applications, the window people
/// drag it across to install it.
fn disk_image(release: &Path, app: &Path, target: &str) -> Result<PathBuf, String> {
    let arch = match target.split('-').next() {
        Some("x86_64") => "x64",
        Some(arch) => arch,
        None => return Err(format!("no architecture in {target}")),
    };
    let directory = release.join("bundle/dmg");
    let staging = directory.join("staging");
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|error| error.to_string())?;
    }
    std::fs::create_dir_all(&staging).map_err(|error| error.to_string())?;
    // ditto keeps the signature and the stapled ticket.
    run(Command::new("ditto").arg(app).arg(staging.join(APP)))?;
    std::os::unix::fs::symlink("/Applications", staging.join("Applications"))
        .map_err(|error| format!("link Applications: {error}"))?;
    let image = directory.join(format!("Egrio_{}_{arch}.dmg", env!("CARGO_PKG_VERSION")));
    run(Command::new("hdiutil")
        .args(["create", "-volname", "Egrio", "-srcfolder"])
        .arg(&staging)
        .args(["-ov", "-format", "UDZO"])
        .arg(&image))?;
    std::fs::remove_dir_all(&staging).map_err(|error| error.to_string())?;
    Ok(image)
}

/// Sends `path` to Apple's notary service and waits for its answer; only an
/// accepted submission passes, and the service's log is shown either way.
fn notarize(path: &Path, profile: &str) -> Result<(), String> {
    eprintln!("xtask: notarizing {}", path.display());
    let answer = finished(
        Command::new("xcrun")
            .args(["notarytool", "submit"])
            .arg(path)
            .args(["--keychain-profile", profile, "--wait"])
            .args(["--output-format", "json"]),
    )?;
    let answer = String::from_utf8_lossy(&answer.stdout).to_string();
    // A string field of the JSON answer, however it is spaced.
    let field = |name: &str| {
        let (_, rest) = answer.split_once(&format!("\"{name}\""))?;
        let rest = rest.trim_start().strip_prefix(':')?.trim_start();
        let (value, _) = rest.strip_prefix('"')?.split_once('"')?;
        Some(value.to_string())
    };
    if let Some(id) = field("id") {
        let _ = run(Command::new("xcrun").args([
            "notarytool",
            "log",
            &id,
            "--keychain-profile",
            profile,
        ]));
    }
    match field("status").as_deref() {
        Some("Accepted") => Ok(()),
        status => Err(format!(
            "notarization of {} ended {}: {answer}",
            path.display(),
            status.unwrap_or("without a status")
        )),
    }
}

fn staple(path: &Path) -> Result<(), String> {
    run(Command::new("xcrun").args(["stapler", "staple"]).arg(path))?;
    run(Command::new("xcrun")
        .args(["stapler", "validate"])
        .arg(path))
}
