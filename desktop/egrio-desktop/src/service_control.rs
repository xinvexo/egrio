//! Headless controls for the macOS service registration. They must run
//! inside Egrio.app: SMAppService registers the service from the calling
//! app's bundle.

use egrio_daemon::privileged_service::{
    macos_service_registration, privileged_service_status, register_macos_service,
    unregister_macos_service,
};

/// Runs a one-shot macOS service registration command selected by the
/// `EGRIO_MACOS_SERVICE` environment variable (`status`, `register` or
/// `unregister`), prints the resulting state as JSON, and returns `true` so
/// the caller skips launching the GUI. Returns `false` when the variable is
/// unset.
pub fn run_from_environment() -> bool {
    let action = match std::env::var("EGRIO_MACOS_SERVICE") {
        Ok(action) => action,
        Err(_) => return false,
    };
    let result = match action.as_str() {
        "status" => Ok(()),
        "register" => register_macos_service().map(drop),
        "unregister" => unregister_macos_service(),
        other => {
            eprintln!("EGRIO_MACOS_SERVICE must be status|register|unregister, got '{other}'");
            std::process::exit(2);
        }
    };
    let report = serde_json::json!({
        "action": action,
        "error": result.err(),
        "registration": macos_service_registration(),
        "status": privileged_service_status(),
    });
    match serde_json::to_string_pretty(&report) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            eprintln!("failed to encode the service report: {error}");
            std::process::exit(1);
        }
    }
    true
}
