//! macOS: the launchd service that applies TUN mode as root for the desktop
//! (see the macOS platform document), and the desktop's side of its packet
//! channel.

mod capabilities;
mod channel;
pub mod host;
mod identity;

pub use capabilities::{MacosServiceHandler, MacosServiceResources, MACOS_SERVICE_CAPABILITIES};
pub use identity::SignedPeers;
