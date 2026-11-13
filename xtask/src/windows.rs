//! The Windows package: `Egrio_<version>_x64-setup.exe`, an NSIS installer
//! (`desktop/egrio/windows/installer.nsi`) that installs the app, the
//! privileged service, the Windows App SDK bootstrapper and Wintun for all
//! users under Program Files, installs the Windows App Runtime when it is
//! missing (`runtime.ps1` beside it), and leaves an uninstaller.
//! `makensis` comes from a pinned NSIS release, checked by SHA-256 and
//! unpacked under `target/nsis/<version>`; docs/platforms/windows.md
//! describes what the installer does.

use std::path::Path;
use std::process::Command;

use super::{host_triple, pinned, root, run, usage, windows_app_sdk, wintun};

const NSIS_VERSION: &str = "3.13";
/// The SHA-256 of `nsis-3.13.zip` as SourceForge serves it; its SHA-1
/// matches the one the project's download page lists.
const NSIS_SHA256: &str = "ba63dffc4410ee89193e1cb5a41989991bd77c61068da17e3156d136b7b0b3d8";

pub struct Options {
    target: String,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self {
            target: host_triple()?,
        };
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--target" => {
                    options.target = args
                        .next()
                        .cloned()
                        .ok_or_else(|| format!("--target needs a value\n{}", usage()))?;
                }
                other => return Err(format!("unknown option {other}\n{}", usage())),
            }
        }
        Ok(options)
    }
}

pub fn package(options: Options) -> Result<(), String> {
    if !options.target.starts_with("x86_64-pc-windows-msvc") {
        return Err(format!(
            "the Windows installer is built for x86_64-pc-windows-msvc, not {}",
            options.target
        ));
    }
    let root = root();
    let release = root.join("target").join(&options.target).join("release");
    build(&root, &options.target)?;
    let app = release.join("egrio.exe");
    let service = release.join("egrio-service.exe");
    for binary in [&app, &service] {
        static_runtime(binary)?;
    }
    run(Command::new(&service).arg("version"))?;
    let sdk = windows_app_sdk::prepare(false)?;
    let (bootstrapper, _) = windows_app_sdk::bootstrapper(&sdk, "win-x64");
    let wintun_distribution = wintun::prepare()?;
    let wintun = wintun::library(&wintun_distribution, "win-x64")?;
    let nsis = root.join("target").join("nsis").join(NSIS_VERSION);
    pinned::unpack(
        &format!(
            "https://downloads.sourceforge.net/project/nsis/NSIS%203/{NSIS_VERSION}/nsis-{NSIS_VERSION}.zip"
        ),
        NSIS_SHA256,
        &nsis,
    )?;
    let bundle = release.join("bundle").join("nsis");
    std::fs::create_dir_all(&bundle).map_err(|error| format!("{}: {error}", bundle.display()))?;
    let version = env!("CARGO_PKG_VERSION");
    let setup = bundle.join(format!("Egrio_{version}_x64-setup.exe"));
    let artwork = bundle.join("artwork");
    super::icons::installer_artwork(&artwork)?;
    // NSIS's File finds nothing on a path with forward slashes.
    let define = |name: &str, value: &Path| {
        format!(
            "/D{name}={}",
            value.display().to_string().replace('/', "\\")
        )
    };
    run(Command::new(
        nsis.join(format!("nsis-{NSIS_VERSION}"))
            .join("makensis.exe"),
    )
    .args(["/V3", "/INPUTCHARSET", "UTF8"])
    .arg(format!("/DVERSION={version}"))
    .arg(format!("/DFILE_VERSION={}", file_version(version)))
    .arg(format!("/DRUNTIME_VERSION={}", windows_app_sdk::VERSION))
    .arg(define("APP", &app))
    .arg(define("SERVICE", &service))
    .arg(define("BOOTSTRAPPER", &bootstrapper))
    .arg(define("WINTUN", &wintun))
    .arg(define(
        "WINTUN_LICENSE",
        &wintun_distribution.join("wintun/LICENSE.txt"),
    ))
    .arg(define("LICENSE", &root.join("LICENSE")))
    .arg(define("ICON", &root.join("desktop/egrio/icons/icon.ico")))
    .arg(define(
        "MARK",
        &root.join("desktop/egrio/icons/app-mark.ico"),
    ))
    .arg(define("ARTWORK", &artwork))
    .arg(define("OUTFILE", &setup))
    .arg(root.join("desktop/egrio/windows/installer.nsi")))?;
    println!("{}", setup.display());
    Ok(())
}

/// The app and the service as release builds for the target.
fn build(root: &Path, target: &str) -> Result<(), String> {
    // The cargo running this task.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    run(Command::new(cargo)
        .current_dir(root)
        .args(["build", "--release", "--target", target])
        .args(["--package", "egrio", "--package", "egrio-service"]))
}

/// Fails when `binary` imports the Visual C++ runtime DLL, which a machine
/// without the Visual C++ Redistributable lacks: the workspace links the C
/// runtime statically on Windows (`.cargo/config.toml`). An import table
/// names its DLLs in ASCII.
fn static_runtime(binary: &Path) -> Result<(), String> {
    let bytes = std::fs::read(binary).map_err(|error| format!("{}: {error}", binary.display()))?;
    let lowered = bytes.to_ascii_lowercase();
    if lowered
        .windows(b"vcruntime140".len())
        .any(|window| window == b"vcruntime140")
    {
        return Err(format!(
            "{} imports the Visual C++ runtime DLL instead of linking it statically",
            binary.display()
        ));
    }
    Ok(())
}

/// A version's numbers as Windows writes a file version: `1.2.3` is
/// `1.2.3.0`, and a pre-release suffix is left out.
fn file_version(version: &str) -> String {
    let numbers = version.split(['-', '+']).next().unwrap_or(version);
    let mut parts: Vec<&str> = numbers.split('.').collect();
    parts.resize(4, "0");
    parts.join(".")
}

#[cfg(test)]
mod tests {
    use super::file_version;

    #[test]
    fn a_file_version_has_four_numbers() {
        assert_eq!(file_version("0.1.0"), "0.1.0.0");
        assert_eq!(file_version("1.2.3-beta.1"), "1.2.3.0");
    }
}
