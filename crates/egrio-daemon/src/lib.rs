//! Non-GUI hosts for Egrio and what a host process needs around the Runtime.
//!
//! `egrio-daemon` holds the `egrio-node` command line (`cli`), the headless
//! server host behind `egrio-server` (`server`), the desktop side of the
//! privileged service -- its status, its one-time install and its start
//! (`privileged_service`) -- and the process-level helpers every
//! long-running host calls at startup (`fd_limit`, `memory_reclaim`). The
//! service's protocol and its capabilities live in `egrio-service`; lifecycle
//! ownership lives in `egrio-runtime` and is assembled through `egrio-sdk`.

// The capture facade: everything that pulls a concrete OS
// capture adapter is gated behind `capture` (default-on), so the server build
// (`--no-default-features --features server`) compiles the fd-limit helper,
// profile handoff, config-driven validation, and server host while linking no
// platform-capture code.
#[cfg(feature = "capture")]
pub mod cli;
pub mod fd_limit;
pub mod memory_reclaim;
#[cfg(feature = "capture")]
pub mod privileged_service;
pub mod profile_handoff;
pub mod server;
pub mod validation;

pub use fd_limit::raise_fd_soft_limit;
pub use memory_reclaim::start_memory_reclaim;
