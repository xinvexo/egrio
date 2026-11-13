mod commands;
mod core;
mod core_config;
mod foreground;
mod service;
mod system_proxy;

pub use service::run_from_env;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliInvocation {
    pub command: CliCommand,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliCommand {
    Help,
    Status,
    Check,
    Run,
    ProxyModeValidation,
    Ipv6ClosedLoopValidation,
    LinuxTunPreflight,
    LinuxTunRun,
    LinuxTunRecover,
    SystemProxyStatus,
    SystemProxyConfig,
    WindowsWfpNetEvents,
}

pub const USER_COMMANDS: &[&str] = &["help", "status", "check", "run"];

impl CliInvocation {
    pub fn parse<I>(args: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = String>,
    {
        let mut args = args.into_iter();
        let command = args.next().unwrap_or_else(|| "status".to_string());
        let command = parse_cli_command(&command)?;
        Ok(Self {
            command,
            args: args.collect(),
        })
    }
}

pub fn cli_arg(args: &[String], index: usize) -> Option<String> {
    args.get(index).cloned()
}

fn parse_cli_command(command: &str) -> Result<CliCommand, String> {
    match command {
        "help" | "-h" | "--help" => Ok(CliCommand::Help),
        "status" => Ok(CliCommand::Status),
        "check" => Ok(CliCommand::Check),
        "run" => Ok(CliCommand::Run),
        "proxy-mode-validation" => Ok(CliCommand::ProxyModeValidation),
        "ipv6-closed-loop-validation" => Ok(CliCommand::Ipv6ClosedLoopValidation),
        "linux-tun-preflight" => Ok(CliCommand::LinuxTunPreflight),
        "linux-tun-run" => Ok(CliCommand::LinuxTunRun),
        "linux-tun-recover" => Ok(CliCommand::LinuxTunRecover),
        "system-proxy-status" => Ok(CliCommand::SystemProxyStatus),
        "system-proxy-config" => Ok(CliCommand::SystemProxyConfig),
        "windows-wfp-net-events" => Ok(CliCommand::WindowsWfpNetEvents),
        _ => Err(format!(
            "unknown command '{command}'. User commands: {}. Diagnostic commands keep explicit platform names.",
            USER_COMMANDS.join(", ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_defaults_to_status() {
        let invocation = CliInvocation::parse(Vec::new()).expect("parse default CLI");

        assert_eq!(invocation.command, CliCommand::Status);
        assert!(invocation.args.is_empty());
    }

    #[test]
    fn cli_accepts_short_core_commands() {
        let invocation = CliInvocation::parse(vec![
            "run".to_string(),
            "--listen".to_string(),
            "127.0.0.1:0".to_string(),
        ])
        .expect("parse run CLI");

        assert_eq!(invocation.command, CliCommand::Run);
        assert_eq!(cli_arg(&invocation.args, 1).as_deref(), Some("127.0.0.1:0"));

        let invocation = CliInvocation::parse(vec!["check".to_string()]).expect("parse check CLI");
        assert_eq!(invocation.command, CliCommand::Check);
    }

    #[test]
    fn cli_rejects_old_native_core_dash_commands() {
        let error = CliInvocation::parse(vec!["native-core-run".to_string()])
            .expect_err("old long command should be rejected");

        assert!(error.contains("unknown command 'native-core-run'"));
        assert!(error.contains("run"));
    }
}
