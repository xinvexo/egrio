//! `cargo xtask check [--full]`: the repository's gates, run from the
//! workspace root, stopping at the first that fails. The static gate is
//! what every commit passes; `--full` adds every test suite and
//! `git diff --check`.

use std::path::Path;
use std::process::Command;

use super::{contracts, dependencies, docs, run};

enum Step {
    Cargo(&'static [&'static str]),
    Git(&'static [&'static str]),
    Check(&'static str, fn(&Path) -> Result<(), String>),
}

const STATIC: &[Step] = &[
    // The repository tasks' own tests: the docs, dependency, contract and
    // benchmark checks.
    Step::Cargo(&["test", "--quiet", "-p", "xtask"]),
    Step::Check("workspace dependencies", dependencies::run),
    Step::Check("macOS contracts", contracts::run),
    Step::Cargo(&["fmt", "--all", "--", "--check"]),
    Step::Cargo(&["check", "--workspace", "--all-targets"]),
    Step::Cargo(&[
        "check",
        "-p",
        "egrio-daemon",
        "--all-targets",
        "--no-default-features",
        "--features",
        "server",
    ]),
    // No workspace member enables the server role by default, so its Core
    // inbounds and their tests compile only here.
    Step::Cargo(&[
        "check",
        "-p",
        "egrio-core",
        "--all-targets",
        "--features",
        "server",
    ]),
    // The instruments read Core and desktop internals behind this feature and
    // nothing else builds it, so it rots unless the gate compiles it too.
    Step::Cargo(&[
        "check",
        "-p",
        "egrio-core",
        "--all-targets",
        "--features",
        "bench-internals",
    ]),
    Step::Cargo(&[
        "check",
        "-p",
        "egrio-desktop",
        "--all-targets",
        "--features",
        "bench-internals",
    ]),
    Step::Check("documentation", docs::run),
];

const FULL: &[Step] = &[
    Step::Cargo(&["test", "--workspace"]),
    Step::Cargo(&[
        "test",
        "-p",
        "egrio-core",
        "-p",
        "egrio-daemon",
        "--features",
        "egrio-core/server,egrio-daemon/server",
    ]),
    // The SDK compiles each platform adapter only behind its feature, so
    // every host tests all three.
    Step::Cargo(&["test", "-p", "egrio-sdk", "--features", "platform-windows"]),
    Step::Cargo(&["test", "-p", "egrio-sdk", "--features", "platform-macos"]),
    Step::Cargo(&["test", "-p", "egrio-sdk", "--features", "platform-linux"]),
    Step::Git(&["diff", "--check"]),
];

pub fn gate(root: &Path, args: &[String]) -> Result<(), String> {
    let full = match args {
        [] => false,
        [flag] if flag == "--full" => true,
        _ => {
            return Err(format!(
                "usage: cargo xtask check [--full]\n{}",
                super::usage()
            ))
        }
    };
    let steps = STATIC.iter().chain(if full { FULL } else { &[] });
    for step in steps {
        match step {
            Step::Cargo(args) => run(&mut cargo(root, args))?,
            Step::Git(args) => run(Command::new("git").current_dir(root).args(*args))?,
            Step::Check(name, check) => {
                eprintln!("xtask: checking {name}");
                check(root)?;
            }
        }
    }
    Ok(())
}

/// The cargo running this task. macOS starts a process with 256
/// descriptors, fewer than some Core tests hold at once, so tests run with
/// the limit the daemon and the desktop raise themselves to
/// (`egrio_daemon::raise_fd_soft_limit`).
fn cargo(root: &Path, args: &[&str]) -> Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = if cfg!(target_os = "macos") && args.first() == Some(&"test") {
        let mut shell = Command::new("/bin/sh");
        shell
            .args(["-c", r#"ulimit -S -n 8192 && exec "$0" "$@""#])
            .arg(cargo);
        shell
    } else {
        Command::new(cargo)
    };
    command.current_dir(root).args(args);
    command
}
