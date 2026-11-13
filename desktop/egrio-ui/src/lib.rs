//! Egrio's desktop interface, written once for every platform. Each window is
//! a pure function from state to a tree of Egrio's own components
//! ([`node`]); the reconciler ([`reconcile`]) turns the change between two
//! trees into patches, and a platform backend ([`backend`]) applies them to
//! native controls. The runtime ([`runtime`]) owns the interface state, runs
//! the product backend's operations and feeds their results back as messages.
//! Nothing here links a platform toolkit.

pub mod backend;
pub mod chart;
pub mod editor;
pub mod format;
pub mod latency;
pub mod messages;
pub mod msg;
pub mod node;
pub mod pages;
pub mod reconcile;
pub mod remembered;
pub mod runtime;
pub mod state;
pub mod text;
pub mod tray;
pub mod view;
