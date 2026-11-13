use std::io::{self, Write};

use crate::cli::{cli_arg, CliCommand, CliInvocation, USER_COMMANDS};
use crate::privileged_service::privileged_service_status;

pub fn run_from_env() -> Result<(), String> {
    // Data-path commands hold hundreds of sockets (UDP session table alone
    // caps at 1024); the platform default soft fd limit (256 on macOS)
    // starves them under load.
    crate::raise_fd_soft_limit();
    crate::start_memory_reclaim();
    let invocation = CliInvocation::parse(std::env::args().skip(1))?;
    let args = invocation.args;

    match invocation.command {
        CliCommand::Help => print_cli_help(),
        CliCommand::Status => print_json(&privileged_service_status()),
        CliCommand::Check => super::core::check(args),
        CliCommand::Run => super::core::run(args),
        CliCommand::ProxyModeValidation => super::core::proxy_mode_validation(args),
        CliCommand::Ipv6ClosedLoopValidation => super::core::ipv6_closed_loop_validation(),
        CliCommand::LinuxTunPreflight => super::commands::linux::print_tun_preflight(),
        CliCommand::LinuxTunRun => {
            super::commands::linux::run_tun(cli_arg(&args, 0), cli_arg(&args, 1))
        }
        CliCommand::LinuxTunRecover => super::commands::linux::recover_tun(cli_arg(&args, 0)),
        CliCommand::SystemProxyStatus => super::system_proxy::print_status(),
        CliCommand::SystemProxyConfig => super::system_proxy::print_config(cli_arg(&args, 0)),
        CliCommand::WindowsWfpNetEvents => super::commands::windows::print_wfp_net_events(
            cli_arg(&args, 0),
            cli_arg(&args, 1),
            cli_arg(&args, 2),
        ),
    }
}

fn print_cli_help() -> Result<(), String> {
    println!("Usage: egrio-node <command> [options]");
    println!();
    println!("Commands:");
    println!("  status    Print service status");
    println!("  check     Validate a runtime config");
    println!("  run       Run the core listener in the foreground");
    println!("  linux-tun-run [profile.json] [checkpoint-dir]   Run Linux TUN capture");
    println!("  linux-tun-preflight   Read-only Linux TUN prerequisites");
    println!("  linux-tun-recover [checkpoint-dir]   Restore unresolved Linux TUN state");
    println!("  help      Show this help");
    println!();
    println!("Core options:");
    println!("  -c, --config <path>        Runtime config JSON/YAML");
    println!("  -D, --directory <path>     Working directory");
    println!("      --listen <addr>       Core SOCKS/HTTP listener, for example 127.0.0.1:7890");
    println!("      --dns-listen <addr>   Core DNS listener, for example 127.0.0.1:5353");
    println!();
    println!(
        "User commands: {}. Platform diagnostic commands keep explicit long names.",
        USER_COMMANDS.join(", ")
    );
    io::stdout().flush().map_err(|error| error.to_string())
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(value).map_err(|e| e.to_string())?
    );
    io::stdout().flush().map_err(|e| e.to_string())
}
