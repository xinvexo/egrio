//! The Linux service process. `egrio-service run-linux-service` serves
//! control sessions on [`LINUX_SERVICE_SOCKET`] and socket marking on
//! [`LINUX_MARK_SOCKET`] for root and the users listed in
//! [`egrio_platform_linux::LINUX_SERVICE_ALLOWED_UIDS`], read at every
//! connection; `install-linux-service --allow-uid <uid>` lists a user and
//! installs or starts the helper, `install-linux-package` starts a package's
//! and `uninstall-linux-service` stops it.
//!
//! Each control connection is one desktop session on its own thread. When
//! the connection ends, the session's resources are released. Each session
//! records the checkpoints it has not restored in the unit's state directory,
//! so whatever a stopped or crashed service leaves in the kernel is released
//! when the next one starts, before it serves anyone; a desktop still running
//! then recovers through the new one, as after any session loss.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use egrio_platform_linux::{
    linux_service_allows, LinuxTunConfig, LINUX_MARK_SOCKET,
    LINUX_PACKAGE_INSTALL_COMMAND as PACKAGE_INSTALL_COMMAND,
    LINUX_SERVICE_INSTALL_COMMAND as INSTALL_COMMAND, LINUX_SERVICE_RUN_COMMAND as RUN_COMMAND,
    LINUX_SERVICE_SOCKET, LINUX_SERVICE_UNINSTALL_COMMAND as UNINSTALL_COMMAND,
};

use super::capabilities::{
    release_left_sessions, LinuxServiceHandler, LinuxServiceResources, LINUX_SERVICE_CAPABILITIES,
};
use super::marking::MarkListener;
use crate::session::ControlServerSession;
use crate::transport::TransportErrorKind;
use crate::unix::{PeerCredentials, PeerPolicy, UnixServerConnection, UnixSocketListener};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceCommand {
    Run,
    Install { uid: u32 },
    InstallPackage,
    Uninstall,
    Version,
}

/// Root, which could apply the capabilities itself, and the listed users.
#[derive(Debug)]
struct ListedUsers;

impl PeerPolicy for ListedUsers {
    fn authorize(&self, _stream: &UnixStream, peer: &PeerCredentials) -> Result<(), String> {
        if linux_service_allows(peer.uid) {
            Ok(())
        } else {
            Err(format!(
                "uid {} is not allowed to control the Egrio service",
                peer.uid
            ))
        }
    }
}

pub fn parse_service_command<I, S>(arguments: I) -> Result<ServiceCommand, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut arguments = arguments.into_iter().map(Into::into);
    match arguments.next().as_deref() {
        None | Some("version") | Some("--version") => Ok(ServiceCommand::Version),
        Some(RUN_COMMAND) => match arguments.next() {
            None => Ok(ServiceCommand::Run),
            Some(argument) => Err(format!("{RUN_COMMAND} does not accept '{argument}'")),
        },
        Some(INSTALL_COMMAND) => {
            let uid = match (
                arguments.next().as_deref(),
                arguments.next(),
                arguments.next(),
            ) {
                (Some("--allow-uid"), Some(uid), None) => uid.parse::<u32>().ok(),
                _ => None,
            }
            .ok_or_else(|| format!("{INSTALL_COMMAND} takes exactly --allow-uid <uid>"))?;
            Ok(ServiceCommand::Install { uid })
        }
        Some(PACKAGE_INSTALL_COMMAND) => match arguments.next() {
            None => Ok(ServiceCommand::InstallPackage),
            Some(_) => Err(format!("{PACKAGE_INSTALL_COMMAND} accepts no arguments")),
        },
        Some(UNINSTALL_COMMAND) => match arguments.next() {
            None => Ok(ServiceCommand::Uninstall),
            Some(_) => Err(format!("{UNINSTALL_COMMAND} accepts no arguments")),
        },
        Some(command) => Err(format!("unknown egrio-service command '{command}'")),
    }
}

pub fn run_from_env() -> Result<(), String> {
    match parse_service_command(std::env::args().skip(1))? {
        ServiceCommand::Run => run_linux_service(),
        ServiceCommand::Install { uid } => super::install::install_linux_service(uid),
        ServiceCommand::InstallPackage => super::install::install_linux_package(),
        ServiceCommand::Uninstall => super::install::uninstall_linux_service(),
        ServiceCommand::Version => {
            let version = crate::protocol_version();
            println!("egrio-service protocol {}.{}", version.major, version.minor);
            Ok(())
        }
    }
}

fn run_linux_service() -> Result<(), String> {
    let config = LinuxTunConfig::default();
    config.validate()?;
    let resources = Arc::new(LinuxServiceResources::default());
    release_left_sessions(&config, &resources);
    let control = UnixSocketListener::bind(Path::new(LINUX_SERVICE_SOCKET), Arc::new(ListedUsers))
        .map_err(|error| format!("failed to listen on {LINUX_SERVICE_SOCKET}: {error}"))?;
    let marking = MarkListener::bind(
        Path::new(LINUX_MARK_SOCKET),
        linux_service_allows,
        config.fwmark,
    )
    .map_err(|error| format!("failed to listen on {LINUX_MARK_SOCKET}: {error}"))?;
    std::thread::spawn(move || marking.serve());
    notify_ready();
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
        let config = config.clone();
        let resources = Arc::clone(&resources);
        // A thread the system will not start ends this connection, not the
        // service: `thread::spawn` panics instead.
        if let Err(error) = std::thread::Builder::new()
            .name("egrio-control".into())
            .spawn(move || serve_session(&connection, config, resources))
        {
            eprintln!("egrio-service: control session thread did not start: {error}");
        }
    }
}

/// Tells systemd the sockets are bound (sd_notify(3) `READY=1`), so starting
/// the `Type=notify` unit returns only once they accept connections. Outside
/// systemd there is no `NOTIFY_SOCKET` and nothing to do.
fn notify_ready() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let sent = UnixDatagram::unbound().and_then(|socket| {
        // A leading '@' names an abstract socket address.
        match path.as_bytes().strip_prefix(b"@") {
            Some(name) => socket.send_to_addr(b"READY=1", &SocketAddr::from_abstract_name(name)?),
            None => socket.send_to(b"READY=1", &path),
        }
    });
    if let Err(error) = sent {
        eprintln!("egrio-service: systemd readiness notification failed: {error}");
    }
}

fn serve_session(
    connection: &UnixServerConnection,
    config: LinuxTunConfig,
    resources: Arc<LinuxServiceResources>,
) {
    let handler = match LinuxServiceHandler::new(config, connection.peer().uid, resources) {
        Ok(handler) => handler,
        Err(error) => {
            eprintln!("egrio-service: control session setup failed: {error}");
            return;
        }
    };
    let session = ControlServerSession::new(
        env!("CARGO_PKG_VERSION"),
        LINUX_SERVICE_CAPABILITIES.to_vec(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_takes_its_users_from_the_list_alone() {
        assert_eq!(
            parse_service_command([RUN_COMMAND]),
            Ok(ServiceCommand::Run)
        );
        assert!(parse_service_command([RUN_COMMAND, "--allow-uid", "1000"]).is_err());
        assert!(parse_service_command(["install"]).is_err());
    }

    #[test]
    fn install_names_exactly_one_user() {
        assert_eq!(
            parse_service_command([INSTALL_COMMAND, "--allow-uid", "1000"]),
            Ok(ServiceCommand::Install { uid: 1000 })
        );
        assert!(parse_service_command([INSTALL_COMMAND]).is_err());
        assert!(parse_service_command([INSTALL_COMMAND, "--allow-uid", "x"]).is_err());
        assert!(parse_service_command([
            INSTALL_COMMAND,
            "--allow-uid",
            "1000",
            "--allow-uid",
            "1"
        ])
        .is_err());
        assert_eq!(
            parse_service_command(Vec::<String>::new()),
            Ok(ServiceCommand::Version)
        );
    }

    #[test]
    fn the_package_install_and_uninstall_take_no_arguments() {
        assert_eq!(
            parse_service_command([PACKAGE_INSTALL_COMMAND]),
            Ok(ServiceCommand::InstallPackage)
        );
        assert!(parse_service_command([PACKAGE_INSTALL_COMMAND, "--allow-uid", "1000"]).is_err());
        assert_eq!(
            parse_service_command([UNINSTALL_COMMAND]),
            Ok(ServiceCommand::Uninstall)
        );
        assert!(parse_service_command([UNINSTALL_COMMAND, "--allow-uid", "1000"]).is_err());
    }
}
