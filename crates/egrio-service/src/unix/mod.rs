//! The Unix domain socket control transport the Linux helper and the macOS
//! service share.

mod transport;

pub use transport::{
    bind_world_connectable, peer_credentials, PeerCredentials, PeerPolicy, UnixServerConnection,
    UnixSocketListener, UnixSocketTransport,
};
