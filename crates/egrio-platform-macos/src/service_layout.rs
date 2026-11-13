//! Where the macOS privileged service lives and how the desktop reaches it.
//! The app bundle carries the service executable and the launchd property
//! list that SMAppService registers (ServiceManagement `SMAppService.h`,
//! `daemonServiceWithPlistName:`), so launchd runs the bundled copy as root
//! once the user allows it in Login Items.

/// The launchd label; the property list in Contents/Library/LaunchDaemons is
/// named after it.
pub const MACOS_SERVICE_LABEL: &str = "com.xinvexo.egrio.service";
pub const MACOS_SERVICE_PLIST: &str = "com.xinvexo.egrio.service.plist";
/// The control socket the service listens on. Every local user can connect;
/// each connection is authorized by the peer's code signature.
pub const MACOS_SERVICE_SOCKET: &str = "/var/run/com.xinvexo.egrio.service.sock";
/// The service executable inside the app bundle, relative to its root
/// (launchd `BundleProgram`).
pub const MACOS_SERVICE_BUNDLE_PROGRAM: &str = "Contents/MacOS/egrio-service";
pub const MACOS_SERVICE_RUN_COMMAND: &str = "run-macos-service";
/// The app's code-signing identifier, which the service requires of a peer
/// signed by its own team.
pub const MACOS_APP_IDENTIFIER: &str = "com.xinvexo.egrio";

#[cfg(test)]
mod tests {
    use super::*;

    /// The property list the app bundle carries runs the bundled service as
    /// root, at load and again whenever it exits.
    #[test]
    fn the_bundled_property_list_runs_the_bundled_service() {
        // A checkout that converts line endings (Git's `core.autocrlf` on
        // Windows) hands this file over with carriage returns.
        let plist = include_str!("../../../desktop/egrio/macos/com.xinvexo.egrio.service.plist")
            .replace("\r\n", "\n");
        assert!(plist.contains("<string>com.xinvexo.egrio.service</string>"));
        assert!(plist
            .contains("<key>BundleProgram</key>\n\t<string>Contents/MacOS/egrio-service</string>"));
        assert!(plist.contains("<string>run-macos-service</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert_eq!(MACOS_SERVICE_PLIST, format!("{MACOS_SERVICE_LABEL}.plist"));
    }
}
