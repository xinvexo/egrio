//! Linux: the root helper that applies TUN mode's capabilities for the
//! desktop user (see the Linux privileged helper design), and the desktop's
//! side of its packet channel and socket marking.

mod capabilities;
mod channel;
mod egress;
pub mod host;
mod install;
mod marking;

pub use capabilities::{LinuxServiceHandler, LinuxServiceResources, LINUX_SERVICE_CAPABILITIES};
pub use egress::ServiceMarkingSocketGuard;
pub use marking::{MarkClient, MarkListener};
