//! The macOS service process. launchd runs the copy inside the app bundle as
//! root (`egrio-service run-macos-service`, from the property list
//! SMAppService registers) and keeps it running; it serves control sessions
//! on [`MACOS_SERVICE_SOCKET`] for peers [`SignedPeers`] admits.
//!
//! Each control connection is one desktop session on its own thread. When
//! the connection ends, its tunnel closes. The process keeps no state across
//! a stop: its network service goes with its dynamic store session, and the
//! exclusion routes a previous process left are removed before anything
//! else.
//!
//! An app update replaces the bundle, and with it the service's executable,
//! while launchd keeps the old process running. That process gives way when
//! the next connection arrives and no session holds the tunnel; launchd then
//! starts the copy in the updated bundle.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use egrio_platform_macos::{MACOS_SERVICE_RUN_COMMAND, MACOS_SERVICE_SOCKET};

use super::capabilities::{MacosServiceHandler, MacosServiceResources, MACOS_SERVICE_CAPABILITIES};
use super::identity::SignedPeers;
use crate::session::ControlServerSession;
use crate::transport::TransportErrorKind;
use crate::unix::{UnixServerConnection, UnixSocketListener};

pub fn run_from_env() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some(MACOS_SERVICE_RUN_COMMAND) => {
            if let Some(argument) = arguments.next() {
                return Err(format!(
                    "{MACOS_SERVICE_RUN_COMMAND} does not accept '{argument}'"
                ));
            }
            run_macos_service()
        }
        None | Some("version") | Some("--version") => {
            let version = crate::protocol_version();
            println!("egrio-service protocol {}.{}", version.major, version.minor);
            Ok(())
        }
        Some(command) => Err(format!("unknown egrio-service command '{command}'")),
    }
}

fn run_macos_service() -> Result<(), String> {
    log::set_logger(&STDERR_LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Info))
        .map_err(|error| error.to_string())?;
    let executable = Executable::current();
    egrio_platform_macos::MacosTunSession::remove_leftovers();
    let control = UnixSocketListener::bind(
        Path::new(MACOS_SERVICE_SOCKET),
        Arc::new(SignedPeers::of_this_service()),
    )
    .map_err(|error| format!("failed to listen on {MACOS_SERVICE_SOCKET}: {error}"))?;
    let resources = Arc::new(MacosServiceResources::default());
    loop {
        // One bad connection never stops the service; only the process
        // ending does.
        let connection = match control.accept() {
            Ok(connection) => connection,
            // A peer gone before it could be identified (a liveness probe)
            // costs nothing.
            Err(error) if error.kind() == TransportErrorKind::Authentication => continue,
            Err(error) => {
                eprintln!("egrio-service: control connection accept failed: {error}");
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
        };
        if executable.as_ref().is_some_and(Executable::replaced) && !resources.holds_tunnel() {
            eprintln!(
                "egrio-service: the app bundle carries a new copy of the service; exiting for it"
            );
            std::process::exit(0);
        }
        let resources = Arc::clone(&resources);
        // A thread the system will not start ends this connection, not the
        // service: `thread::spawn` panics instead.
        if let Err(error) = std::thread::Builder::new()
            .name("egrio-control".into())
            .spawn(move || serve_session(&connection, resources))
        {
            eprintln!("egrio-service: control session thread did not start: {error}");
        }
    }
}

/// The service's executable file as it was when this process started.
struct Executable {
    path: PathBuf,
    identity: (u64, u64),
}

impl Executable {
    fn current() -> Option<Self> {
        let path = std::env::current_exe().ok()?;
        let identity = file_identity(&path)?;
        Some(Self { path, identity })
    }

    /// Whether another file, or none, now sits at the path.
    fn replaced(&self) -> bool {
        file_identity(&self.path) != Some(self.identity)
    }
}

fn file_identity(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| (metadata.dev(), metadata.ino()))
}

fn serve_session(connection: &UnixServerConnection, resources: Arc<MacosServiceResources>) {
    let handler = MacosServiceHandler::new(resources);
    let session = ControlServerSession::new(
        env!("CARGO_PKG_VERSION"),
        MACOS_SERVICE_CAPABILITIES.to_vec(),
    );
    loop {
        match connection.serve_once(&session, &handler) {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                eprintln!("egrio-service: control request failed: {error}");
                break;
            }
        }
    }
    handler.end_session();
}

/// The platform crate's log lines, on the standard error launchd keeps
/// (the property list's `StandardErrorPath`).
struct StderrLogger;

static STDERR_LOGGER: StderrLogger = StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!("egrio-service: {}: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}
