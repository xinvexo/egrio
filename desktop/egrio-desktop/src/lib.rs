//! Egrio's desktop product backend: profiles and their sources, settings, the
//! process's fixed Runtime host, the connection and rule-hit history, and the
//! operations a desktop host offers the user. It links no UI toolkit; a
//! desktop host drives it and forwards its events to windows and the tray.

pub mod active_profile_propagation;
pub mod app_paths;
pub mod async_runtime;
#[cfg(feature = "bench-internals")]
pub mod bench;
pub mod configuration;
pub mod connection_history;
pub mod desktop_behavior;
pub mod events;
pub mod exit;
pub mod geodata;
pub mod ipv6_settings;
pub mod logging;
pub mod models;
pub mod network_probe;
pub mod operations;
pub mod policy_watch;
pub mod profile_configuration;
pub mod profile_network_settings;
pub mod profile_service;
pub mod profile_source;
pub mod profile_store;
pub mod remote_fetch;
pub mod rule_provider_fetch;
pub mod runtime;
#[cfg(unix)]
pub mod runtime_owner;
#[cfg(target_os = "macos")]
pub mod service_control;
pub mod system_proxy_guard;
pub mod tun_environment;
pub mod ui_text;
pub mod updates;
