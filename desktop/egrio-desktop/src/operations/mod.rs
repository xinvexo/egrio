//! The operations a desktop host offers the user, split by domain. Each maps
//! its arguments onto store reads and writes and Runtime host calls; a host
//! wires them to its windows, tray and menus without holding any of their
//! state.

pub mod capture;
pub mod egress;
pub mod profiles;
pub mod settings;
pub mod telemetry;
