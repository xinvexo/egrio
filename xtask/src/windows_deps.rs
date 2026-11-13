//! `cargo xtask windows-deps`: the DLLs the Windows builds load from beside
//! their executables, staged in the debug and release directories of the
//! host's or the given target's builds: the Windows App SDK bootstrapper
//! that `egrio.exe` loads and `wintun.dll` that `egrio-service.exe` loads.
//! `--bindings` also regenerates the WinUI bindings. It runs on any host.

use std::path::PathBuf;

use super::{host_triple, root, usage, windows_app_sdk, wintun};

pub struct Options {
    bindings: bool,
    /// The Rust target whose builds get the DLLs; the host's builds when
    /// absent.
    target: Option<String>,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self {
            bindings: false,
            target: None,
        };
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            match flag.as_str() {
                "--bindings" => options.bindings = true,
                "--target" => {
                    options.target = Some(
                        args.next()
                            .cloned()
                            .ok_or_else(|| format!("--target needs a value\n{}", usage()))?,
                    );
                }
                other => return Err(format!("unknown option {other}\n{}", usage())),
            }
        }
        Ok(options)
    }
}

pub fn prepare(options: Options) -> Result<(), String> {
    let triple = match &options.target {
        Some(target) => target.clone(),
        None => host_triple()?,
    };
    let architecture = match triple.split('-').next() {
        Some("x86_64") => "win-x64",
        Some("aarch64") => "win-arm64",
        Some("i686") => "win-x86",
        _ => return Err(format!("no Windows build for {triple}")),
    };
    let sdk = windows_app_sdk::prepare(options.bindings)?;
    let (bootstrapper, bootstrapper_name) = windows_app_sdk::bootstrapper(&sdk, architecture);
    let wintun = wintun::library(&wintun::prepare()?, architecture)?;
    let target_dir = root().join("target");
    let builds: Vec<PathBuf> = match &options.target {
        Some(target) => vec![
            target_dir.join(target).join("debug"),
            target_dir.join(target).join("release"),
        ],
        None => vec![target_dir.join("debug"), target_dir.join("release")],
    };
    for build in builds {
        std::fs::create_dir_all(&build).map_err(|error| format!("{}: {error}", build.display()))?;
        for (dll, name) in [(&bootstrapper, bootstrapper_name), (&wintun, "wintun.dll")] {
            std::fs::copy(dll, build.join(name))
                .map_err(|error| format!("{}: {error}", dll.display()))?;
            eprintln!("xtask: staged {name} in {}", build.display());
        }
    }
    Ok(())
}
