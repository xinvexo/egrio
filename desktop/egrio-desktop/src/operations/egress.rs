//! The dashboard's egress probe through the running Core.

use crate::models::PublicIpInfo;
use crate::network_probe;
use crate::runtime::DesktopRuntime;
use egrio_core::{NativeCoreState, NativeCoreStatus};

/// The egress addresses, location and operator of the running Core's path.
pub async fn public_ip_info(runtime: &DesktopRuntime) -> Result<PublicIpInfo, String> {
    let core_status = runtime
        .core_status()
        .unwrap_or_else(super::telemetry::stopped_native_core_status);
    let listen_addr = public_ip_probe_listen_addr(&core_status)?;
    network_probe::get_public_ip_info(listen_addr).await
}

fn public_ip_probe_listen_addr(core_status: &NativeCoreStatus) -> Result<&str, String> {
    match core_status.state {
        NativeCoreState::Running => core_status
            .listen_addr
            .as_deref()
            .ok_or_else(|| "native Core is running without a listen address".to_string()),
        NativeCoreState::Stopped => Err("native Core is not running".into()),
        NativeCoreState::Stopping => Err("native Core is stopping".into()),
        NativeCoreState::Failed => Err(core_status
            .last_error
            .as_deref()
            .map(|error| format!("native Core failed: {error}"))
            .unwrap_or_else(|| "native Core failed".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn core_status(state: NativeCoreState, listen_addr: Option<&str>) -> NativeCoreStatus {
        NativeCoreStatus {
            state,
            listen_addr: listen_addr.map(str::to_string),
            listener_fallback: None,
            dns_listen_addr: None,
            started_at_unix: None,
            updated_at_unix: 0,
            active_sessions: 0,
            accepted_sessions: 0,
            completed_sessions: 0,
            failed_sessions: 0,
            last_error: None,
        }
    }

    #[test]
    fn public_ip_probe_uses_only_a_running_core_listener() {
        let running = core_status(NativeCoreState::Running, Some("127.0.0.1:7890"));
        let stopped = core_status(NativeCoreState::Stopped, None);
        let running_without_listener = core_status(NativeCoreState::Running, None);

        assert_eq!(public_ip_probe_listen_addr(&running), Ok("127.0.0.1:7890"));
        assert!(public_ip_probe_listen_addr(&stopped).is_err());
        assert!(public_ip_probe_listen_addr(&running_without_listener).is_err());
    }
}
