//! The `egrio-node` binary: the combined-role packaging. Built
//! with both `capture` and `server` features, it carries the OS capture host and
//! the server-assembly host in one artifact — the single binary that can run as
//! a client or a server. The role-locked packagings stay separate
//! (`egrio-service` = capture only, `egrio-server` = server only); role is a
//! packaging choice over one role-agnostic core, so this binary is the union of
//! the other two rather than a third code path.
//!
//! Dispatch: a `server <config>` subcommand runs the server role over
//! [`egrio_daemon::server::run`]; every other invocation is the capture/service
//! CLI ([`egrio_daemon::cli::run_from_env`], which parses argv itself). `main`
//! stays synchronous because the capture CLI manages its own async runtime — a
//! `#[tokio::main]` here would nest runtimes and panic — so only the server
//! branch spins up a runtime, for its one async call.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "egrio-node".to_string());

    // The `server` subcommand selects the server-assembly role. Peeking argv here
    // is harmless: the capture branch below re-reads argv from the environment.
    if matches!(args.next().as_deref(), Some("server")) {
        let Some(config_path) = args.next() else {
            eprintln!("usage: {program} server <server-config.json>");
            return ExitCode::FAILURE;
        };
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(runtime) => runtime,
            Err(error) => {
                eprintln!("{program}: failed to start async runtime: {error}");
                return ExitCode::FAILURE;
            }
        };
        return match runtime.block_on(egrio_daemon::server::run(&config_path)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{program}: {error}");
                ExitCode::FAILURE
            }
        };
    }

    match egrio_daemon::cli::run_from_env() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
