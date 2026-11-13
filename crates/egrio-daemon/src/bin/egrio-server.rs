//! The `egrio-server` binary: a thin entry point over the
//! server-assembly host in the daemon library. Built with
//! `--no-default-features --features server`, it links no platform-capture
//! adapter — the capture facade is gated off. Verify with
//! `cargo tree -p egrio-daemon --no-default-features --features server`.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "egrio-server".to_string());
    let Some(config_path) = args.next() else {
        eprintln!("usage: {program} <server-config.json>");
        return ExitCode::FAILURE;
    };

    match egrio_daemon::server::run(&config_path).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("egrio-server: {error}");
            ExitCode::FAILURE
        }
    }
}
