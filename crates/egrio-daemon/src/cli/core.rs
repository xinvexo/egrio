use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::core_config::{load_config, RuntimeConfig};
use crate::cli::foreground::ForegroundShutdownGuard;
use crate::profile_handoff::default_direct_profile;
use egrio_core::{CoreStartInputs, NativeCoreCaptureConfig, NativeCoreState, NativeCoreStatus};
use egrio_runtime::{
    CoreConfigSource, RuntimeCoreSpec, RuntimeId, RuntimePlatformSpec, RuntimeSpec,
};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeCoreCliOptions {
    config_path: Option<PathBuf>,
    directory: Option<PathBuf>,
    listen_addr: Option<SocketAddr>,
    dns_listen_addr: Option<SocketAddr>,
    disable_color: bool,
}

#[derive(Debug)]
struct PreparedNativeCoreCliConfig {
    config: RuntimeConfig,
    config_path: Option<String>,
    working_dir: String,
    disable_color: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NativeCoreCliPrepareMode {
    Check,
    Run,
}

#[derive(Debug, Serialize)]
struct NativeCoreCliCheckReport {
    ok: bool,
    config_path: Option<String>,
    working_dir: String,
    profile_id: String,
    profile_name: String,
    listen_addr: Option<String>,
    dns_listen_addr: Option<String>,
    disable_color: bool,
}

#[derive(Debug, Serialize)]
struct NativeCoreCliRunStartedReport {
    event: &'static str,
    config_path: Option<String>,
    working_dir: String,
    profile_id: String,
    profile_name: String,
    listen_addr: Option<String>,
    dns_listen_addr: Option<String>,
    status: NativeCoreStatus,
    disable_color: bool,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct NativeCoreCliRunStoppedReport {
    event: &'static str,
    shutdown_requested: bool,
    status: NativeCoreStatus,
    error: Option<String>,
    warnings: Vec<String>,
}

#[derive(Debug)]
enum NativeCoreForegroundExit {
    ShutdownRequested,
    CoreStopped(NativeCoreStatus),
}

pub(crate) fn check<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
{
    let prepared = prepare_native_core_cli_config(args, NativeCoreCliPrepareMode::Check)?;
    print_json(&NativeCoreCliCheckReport {
        ok: true,
        config_path: prepared.config_path,
        working_dir: prepared.working_dir,
        profile_id: prepared.config.profile.id,
        profile_name: prepared.config.profile.name,
        listen_addr: prepared
            .config
            .listen_addr
            .map(|listen_addr| listen_addr.to_string()),
        dns_listen_addr: prepared
            .config
            .dns_listen_addr
            .map(|dns_listen_addr| dns_listen_addr.to_string()),
        disable_color: prepared.disable_color,
    })
}

pub(crate) fn run<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
{
    let prepared = prepare_native_core_cli_config(args, NativeCoreCliPrepareMode::Run)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("egrio-native-core-cli")
        .build()
        .map_err(|error| format!("failed to create native core CLI runtime: {error}"))?;

    runtime.block_on(run_foreground(prepared))
}

pub(crate) fn proxy_mode_validation<I>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = String>,
{
    let runtime_profile_path = args.into_iter().next().ok_or_else(|| {
        "proxy-mode-validation requires a runtime profile path (see scripts/validation/profiles)"
            .to_string()
    })?;
    let report = crate::validation::run_proxy_mode_validation(runtime_profile_path)?;
    print_json(&report)?;
    if report.ok {
        Ok(())
    } else {
        Err(format!(
            "proxy-mode validation is blocked: {}",
            report.blockers.join("; ")
        ))
    }
}

pub(crate) fn ipv6_closed_loop_validation() -> Result<(), String> {
    let report = crate::validation::run_ipv6_closed_loop_validation()?;
    print_json(&report)?;
    if report.ok {
        Ok(())
    } else {
        Err(format!(
            "IPv6 closed-loop validation is blocked: {}",
            report.blockers.join("; ")
        ))
    }
}

async fn run_foreground(prepared: PreparedNativeCoreCliConfig) -> Result<(), String> {
    // The Core's QUIC pacing needs timers finer than Windows gives a process
    // that does not ask; held until this foreground run ends.
    #[cfg(windows)]
    let _timer_resolution = egrio_platform_windows::FineTimerResolution::hold()
        .inspect_err(|error| eprintln!("timer resolution stays at the default: {error}"))
        .ok();
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let _foreground_shutdown = ForegroundShutdownGuard::install(Arc::clone(&shutdown_signal))?;
    let mut warnings = Vec::new();

    if prepared.config.capture != NativeCoreCaptureConfig::default() {
        warnings.push(
            "runtime capture settings are ignored by run; use capture for platform capture".into(),
        );
    }

    let runtime_id = RuntimeId::new();
    let sdk = EgrioSdk::builder()
        .checkpoint_store(Arc::new(InMemoryCheckpointStore::new()))
        .core_config(Arc::new(NativeCoreCliCoreConfig {
            profile: prepared.config.profile.clone(),
            egress: prepared.config.egress.clone(),
        }))
        .build()
        .map_err(|error| format!("failed to assemble native core SDK: {error}"))?;
    let runtime_spec = RuntimeSpec::with_core(
        runtime_id,
        Some(RuntimeCoreSpec {
            listen_addr: prepared.config.listen_addr,
            dns_listen_addr: prepared.config.dns_listen_addr,
            listen_port_fallback: false,
        }),
        RuntimePlatformSpec::default(),
    )
    .map_err(|error| format!("failed to build native core Runtime spec: {error}"))?;
    let runtime = sdk
        .create_runtime(runtime_spec)
        .await
        .map_err(|error| format!("failed to create native core Runtime: {error}"))?;
    runtime
        .start()
        .await
        .map_err(|error| format!("failed to start native core Runtime: {error}"))?;
    let status = runtime.core_status();
    warnings.sort();
    warnings.dedup();

    print_json(&NativeCoreCliRunStartedReport {
        event: "native-core-started",
        config_path: prepared.config_path.clone(),
        working_dir: prepared.working_dir.clone(),
        profile_id: prepared.config.profile.id.clone(),
        profile_name: prepared.config.profile.name.clone(),
        listen_addr: status.listen_addr.clone(),
        dns_listen_addr: status.dns_listen_addr.clone(),
        status,
        disable_color: prepared.disable_color,
        warnings: warnings.clone(),
    })?;

    let foreground_exit =
        wait_for_native_core_foreground_exit(runtime.as_ref(), Arc::clone(&shutdown_signal))
            .await?;
    let (shutdown_requested, stopped_error, final_status) = match foreground_exit {
        NativeCoreForegroundExit::ShutdownRequested => {
            let stop_result = tokio::time::timeout(Duration::from_secs(2), runtime.stop()).await;
            let stop_error = match stop_result {
                Ok(Ok(_)) => None,
                Ok(Err(error)) => Some(format!("failed to stop native core Runtime: {error}")),
                Err(_) => {
                    warnings.push(
                        "native core Runtime did not stop within the foreground shutdown grace period"
                            .into(),
                    );
                    None
                }
            };
            (
                true,
                stop_error,
                wait_for_native_core_stopped(runtime.as_ref(), Duration::from_secs(2)).await,
            )
        }
        NativeCoreForegroundExit::CoreStopped(status) => {
            let error = status.last_error.clone().unwrap_or_else(|| {
                format!(
                    "native core exited unexpectedly with state {:?}",
                    status.state
                )
            });
            (false, Some(error), status)
        }
    };

    if shutdown_requested && final_status.state != NativeCoreState::Stopped {
        warnings.push(format!(
            "native core did not fully stop within the foreground shutdown grace period; current state is {:?}",
            final_status.state
        ));
    }

    print_json(&NativeCoreCliRunStoppedReport {
        event: "native-core-stopped",
        shutdown_requested,
        status: final_status,
        error: stopped_error.clone(),
        warnings,
    })?;

    if let Err(error) = sdk.remove_runtime(runtime_id).await {
        eprintln!("warning: failed to remove native core Runtime from SDK registry: {error}");
    }

    match stopped_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[derive(Debug)]
struct NativeCoreCliCoreConfig {
    profile: egrio_core::RuntimeProfile,
    egress: egrio_core::NativeCoreEgressConfig,
}

impl CoreConfigSource for NativeCoreCliCoreConfig {
    fn load(&self) -> Result<CoreStartInputs, String> {
        Ok(CoreStartInputs {
            capture: Default::default(),
            profile: self.profile.clone(),
            egress: self.egress.clone(),
            egress_socket_guard: None,
            flow_scanner: platform_flow_scanner(),
            fake_ip_mappings: None,
        })
    }
}

/// The local platform's socket-ownership scanner, so process rules match
/// this listener's clients as they do in the desktop app.
fn platform_flow_scanner() -> Option<std::sync::Arc<dyn egrio_core::FlowScanner>> {
    #[cfg(target_os = "linux")]
    {
        Some(std::sync::Arc::new(egrio_platform_linux::LinuxFlowScanner))
    }
    #[cfg(windows)]
    {
        Some(std::sync::Arc::new(
            egrio_platform_windows::WindowsFlowScanner::default(),
        ))
    }
    #[cfg(target_os = "macos")]
    {
        Some(std::sync::Arc::new(
            egrio_platform_macos::MacosFlowScanner::default(),
        ))
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        None
    }
}

fn prepare_native_core_cli_config<I>(
    args: I,
    mode: NativeCoreCliPrepareMode,
) -> Result<PreparedNativeCoreCliConfig, String>
where
    I: IntoIterator<Item = String>,
{
    let options = parse_native_core_cli_args(args)?;
    let working_dir_path = native_core_cli_working_dir(options.directory.as_ref())?;
    prepare_native_core_cli_working_dir(&working_dir_path, mode)?;
    let resolved_config_path =
        native_core_cli_config_path(options.config_path.as_ref(), &working_dir_path);

    if mode == NativeCoreCliPrepareMode::Run {
        std::env::set_current_dir(&working_dir_path).map_err(|error| {
            format!(
                "failed to enter native core working directory {}: {error}",
                working_dir_path.display()
            )
        })?;
    }

    let working_dir = working_dir_path.display().to_string();
    let config_path = resolved_config_path
        .as_ref()
        .map(|path| path.display().to_string());
    let mut config = match resolved_config_path.as_ref() {
        Some(config_path) => load_config(config_path).map_err(|error| error.to_string())?,
        None => RuntimeConfig::from_profile(default_direct_profile()),
    };

    if let Some(listen_addr) = options.listen_addr {
        config.listen_addr = Some(listen_addr);
    }
    if let Some(dns_listen_addr) = options.dns_listen_addr {
        config.dns_listen_addr = Some(dns_listen_addr);
    }

    Ok(PreparedNativeCoreCliConfig {
        config,
        config_path,
        working_dir,
        disable_color: options.disable_color,
    })
}

fn native_core_cli_working_dir(directory: Option<&PathBuf>) -> Result<PathBuf, String> {
    let current_dir = std::env::current_dir()
        .map_err(|error| format!("failed to read native core working directory: {error}"))?;
    let Some(directory) = directory else {
        return Ok(current_dir);
    };

    if directory.is_absolute() {
        Ok(directory.clone())
    } else {
        Ok(current_dir.join(directory))
    }
}

fn prepare_native_core_cli_working_dir(
    working_dir: &Path,
    mode: NativeCoreCliPrepareMode,
) -> Result<(), String> {
    match mode {
        NativeCoreCliPrepareMode::Check => {
            if working_dir.exists() && !working_dir.is_dir() {
                return Err(format!(
                    "native core working directory {} exists but is not a directory",
                    working_dir.display()
                ));
            }
            Ok(())
        }
        NativeCoreCliPrepareMode::Run => std::fs::create_dir_all(working_dir).map_err(|error| {
            format!(
                "failed to create native core working directory {}: {error}",
                working_dir.display()
            )
        }),
    }
}

fn native_core_cli_config_path(
    config_path: Option<&PathBuf>,
    working_dir: &Path,
) -> Option<PathBuf> {
    config_path.map(|path| {
        if path.is_absolute() {
            path.clone()
        } else {
            working_dir.join(path)
        }
    })
}

fn parse_native_core_cli_args<I>(args: I) -> Result<NativeCoreCliOptions, String>
where
    I: IntoIterator<Item = String>,
{
    let mut options = NativeCoreCliOptions {
        config_path: None,
        directory: None,
        listen_addr: None,
        dns_listen_addr: None,
        disable_color: false,
    };
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let value = next_native_core_cli_value(&mut args, &arg)?;
                set_native_core_cli_config_path(&mut options, PathBuf::from(value))?;
            }
            "-D" | "--directory" => {
                let value = next_native_core_cli_value(&mut args, &arg)?;
                set_native_core_cli_directory(&mut options, PathBuf::from(value))?;
            }
            "--listen" => {
                let value = next_native_core_cli_value(&mut args, &arg)?;
                options.listen_addr = Some(parse_native_core_cli_socket_addr(&value, "--listen")?);
            }
            "--dns-listen" => {
                let value = next_native_core_cli_value(&mut args, &arg)?;
                options.dns_listen_addr =
                    Some(parse_native_core_cli_socket_addr(&value, "--dns-listen")?);
            }
            "--disable-color" => {
                options.disable_color = true;
            }
            "--" => {
                let value = next_native_core_cli_value(&mut args, "--")?;
                set_native_core_cli_config_path(&mut options, PathBuf::from(value))?;
                if let Some(extra) = args.next() {
                    return Err(format!(
                        "unexpected native core argument '{extra}' after config path"
                    ));
                }
            }
            _ if arg.starts_with("--config=") => {
                let value = arg.trim_start_matches("--config=");
                if value.is_empty() {
                    return Err("--config requires a path".into());
                }
                set_native_core_cli_config_path(&mut options, PathBuf::from(value))?;
            }
            _ if arg.starts_with("--directory=") => {
                let value = arg.trim_start_matches("--directory=");
                if value.is_empty() {
                    return Err("--directory requires a path".into());
                }
                set_native_core_cli_directory(&mut options, PathBuf::from(value))?;
            }
            _ if arg.starts_with("--listen=") => {
                let value = arg.trim_start_matches("--listen=");
                if value.is_empty() {
                    return Err("--listen requires a socket address".into());
                }
                options.listen_addr = Some(parse_native_core_cli_socket_addr(value, "--listen")?);
            }
            _ if arg.starts_with("--dns-listen=") => {
                let value = arg.trim_start_matches("--dns-listen=");
                if value.is_empty() {
                    return Err("--dns-listen requires a socket address".into());
                }
                options.dns_listen_addr =
                    Some(parse_native_core_cli_socket_addr(value, "--dns-listen")?);
            }
            _ if arg.starts_with('-') => {
                return Err(format!("unknown native core option '{arg}'"));
            }
            _ => {
                set_native_core_cli_config_path(&mut options, PathBuf::from(arg))?;
            }
        }
    }

    Ok(options)
}

fn next_native_core_cli_value(
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn set_native_core_cli_config_path(
    options: &mut NativeCoreCliOptions,
    config_path: PathBuf,
) -> Result<(), String> {
    if options.config_path.is_some() {
        return Err("native core config path was specified more than once".into());
    }
    options.config_path = Some(config_path);
    Ok(())
}

fn set_native_core_cli_directory(
    options: &mut NativeCoreCliOptions,
    directory: PathBuf,
) -> Result<(), String> {
    if options.directory.is_some() {
        return Err("native core working directory was specified more than once".into());
    }
    options.directory = Some(directory);
    Ok(())
}

fn parse_native_core_cli_socket_addr(value: &str, flag: &str) -> Result<SocketAddr, String> {
    value
        .parse::<SocketAddr>()
        .map_err(|error| format!("{flag} requires a socket address, got '{value}': {error}"))
}

async fn wait_for_native_core_stopped(
    runtime: &egrio_runtime::Runtime,
    timeout: Duration,
) -> NativeCoreStatus {
    let started_at = Instant::now();
    loop {
        let status = runtime.core_status();
        if matches!(
            status.state,
            NativeCoreState::Stopped | NativeCoreState::Failed
        ) {
            return status;
        }
        if started_at.elapsed() >= timeout {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(windows)]
async fn wait_for_native_core_foreground_exit(
    runtime: &egrio_runtime::Runtime,
    shutdown_signal: Arc<AtomicBool>,
) -> Result<NativeCoreForegroundExit, String> {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        let status = runtime.core_status();
        if matches!(
            status.state,
            NativeCoreState::Stopped | NativeCoreState::Failed
        ) {
            return Ok(NativeCoreForegroundExit::CoreStopped(status));
        }
        if shutdown_signal.load(Ordering::SeqCst) {
            return Ok(NativeCoreForegroundExit::ShutdownRequested);
        }

        tokio::select! {
            result = &mut ctrl_c => {
                result.map_err(|error| format!("failed to listen for native core Ctrl-C: {error}"))?;
                shutdown_signal.store(true, Ordering::SeqCst);
                return Ok(NativeCoreForegroundExit::ShutdownRequested);
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

#[cfg(unix)]
async fn wait_for_native_core_foreground_exit(
    runtime: &egrio_runtime::Runtime,
    shutdown_signal: Arc<AtomicBool>,
) -> Result<NativeCoreForegroundExit, String> {
    let mut interrupt =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|error| format!("failed to listen for native core SIGINT: {error}"))?;
    let mut terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|error| format!("failed to listen for native core SIGTERM: {error}"))?;
    let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .map_err(|error| format!("failed to listen for native core SIGHUP: {error}"))?;

    loop {
        let status = runtime.core_status();
        if matches!(
            status.state,
            NativeCoreState::Stopped | NativeCoreState::Failed
        ) {
            return Ok(NativeCoreForegroundExit::CoreStopped(status));
        }
        if shutdown_signal.load(Ordering::SeqCst) {
            return Ok(NativeCoreForegroundExit::ShutdownRequested);
        }

        tokio::select! {
            _ = interrupt.recv() => {
                shutdown_signal.store(true, Ordering::SeqCst);
                return Ok(NativeCoreForegroundExit::ShutdownRequested);
            }
            _ = terminate.recv() => {
                shutdown_signal.store(true, Ordering::SeqCst);
                return Ok(NativeCoreForegroundExit::ShutdownRequested);
            }
            _ = hangup.recv() => {
                shutdown_signal.store(true, Ordering::SeqCst);
                return Ok(NativeCoreForegroundExit::ShutdownRequested);
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

#[cfg(not(any(windows, unix)))]
async fn wait_for_native_core_foreground_exit(
    runtime: &egrio_runtime::Runtime,
    shutdown_signal: Arc<AtomicBool>,
) -> Result<NativeCoreForegroundExit, String> {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    loop {
        let status = runtime.core_status();
        if matches!(
            status.state,
            NativeCoreState::Stopped | NativeCoreState::Failed
        ) {
            return Ok(NativeCoreForegroundExit::CoreStopped(status));
        }
        if shutdown_signal.load(Ordering::SeqCst) {
            return Ok(NativeCoreForegroundExit::ShutdownRequested);
        }

        tokio::select! {
            result = &mut ctrl_c => {
                result.map_err(|error| format!("failed to listen for native core Ctrl-C: {error}"))?;
                shutdown_signal.store(true, Ordering::SeqCst);
                return Ok(NativeCoreForegroundExit::ShutdownRequested);
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<(), String> {
    let document = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    println!("{document}");
    io::stdout().flush().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn native_core_cli_options_accept_reference_style_flags() {
        let options = parse_native_core_cli_args(native_core_args(&[
            "-D",
            r"C:\egrio-runtime",
            "-c",
            "runtime.yaml",
            "--listen",
            "127.0.0.1:7890",
            "--dns-listen",
            "127.0.0.1:5353",
            "--disable-color",
        ]))
        .expect("native core CLI options should parse");

        assert_eq!(options.directory, Some(PathBuf::from(r"C:\egrio-runtime")));
        assert_eq!(options.config_path, Some(PathBuf::from("runtime.yaml")));
        assert_eq!(options.listen_addr, Some("127.0.0.1:7890".parse().unwrap()));
        assert_eq!(
            options.dns_listen_addr,
            Some("127.0.0.1:5353".parse().unwrap())
        );
        assert!(options.disable_color);
    }

    #[test]
    fn native_core_cli_options_accept_equals_and_bare_config_path() {
        let options = parse_native_core_cli_args(native_core_args(&[
            "--directory=runtime-dir",
            "--listen=127.0.0.1:0",
            "--dns-listen=127.0.0.1:0",
            "runtime.json",
        ]))
        .expect("native core CLI options should parse");

        assert_eq!(options.directory, Some(PathBuf::from("runtime-dir")));
        assert_eq!(options.config_path, Some(PathBuf::from("runtime.json")));
        assert_eq!(options.listen_addr, Some("127.0.0.1:0".parse().unwrap()));
        assert_eq!(
            options.dns_listen_addr,
            Some("127.0.0.1:0".parse().unwrap())
        );
    }

    #[test]
    fn native_core_cli_options_reject_duplicate_config_path() {
        let error = parse_native_core_cli_args(native_core_args(&[
            "-c",
            "runtime-a.json",
            "runtime-b.json",
        ]))
        .expect_err("duplicate config path should fail");

        assert!(error.contains("specified more than once"));
    }

    #[test]
    fn native_core_cli_options_reject_missing_option_value() {
        let error = parse_native_core_cli_args(native_core_args(&["--listen"]))
            .expect_err("missing listen value should fail");

        assert!(error.contains("--listen requires a value"));
    }

    #[test]
    fn native_core_cli_options_reject_invalid_socket_addr() {
        let error = parse_native_core_cli_args(native_core_args(&["--dns-listen", "127.0.0.1"]))
            .expect_err("invalid DNS listen socket addr should fail");

        assert!(error.contains("--dns-listen requires a socket address"));
    }

    #[test]
    fn native_core_check_prepare_does_not_create_or_enter_working_directory() {
        let directory = std::env::temp_dir().join(format!(
            "egrio-native-core-check-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos()
        ));
        let current_dir = std::env::current_dir().expect("current dir");

        let prepared = prepare_native_core_cli_config(
            native_core_args(&[
                "-D",
                directory.to_str().expect("temp path is UTF-8"),
                "--listen",
                "127.0.0.1:0",
            ]),
            NativeCoreCliPrepareMode::Check,
        )
        .expect("native core check prepare succeeds");

        assert_eq!(PathBuf::from(prepared.working_dir), directory);
        assert!(!directory.exists());
        assert_eq!(std::env::current_dir().expect("current dir"), current_dir);
    }

    fn native_core_args(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).to_string()).collect()
    }
}
