use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsIpv6RequestedPolicy {
    Auto,
    Tunnel,
    Block,
    Off,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsIpv6ResolvedPosture {
    Tunnel,
    Block,
    Off,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsIpv6RuntimeState {
    pub requested_policy: WindowsIpv6RequestedPolicy,
    pub resolved_posture: WindowsIpv6ResolvedPosture,
}

impl WindowsIpv6RuntimeState {
    // The DTO crosses to TS on every platform, but only the Windows Runtime
    // constructs it.
    #[cfg(any(windows, test))]
    #[must_use]
    pub fn from_capture(
        requested_policy: WindowsIpv6RequestedPolicy,
        capture_ipv6_enabled: bool,
    ) -> Self {
        let resolved_posture = match requested_policy {
            WindowsIpv6RequestedPolicy::Auto => {
                if capture_ipv6_enabled {
                    WindowsIpv6ResolvedPosture::Tunnel
                } else {
                    WindowsIpv6ResolvedPosture::Block
                }
            }
            WindowsIpv6RequestedPolicy::Tunnel => WindowsIpv6ResolvedPosture::Tunnel,
            WindowsIpv6RequestedPolicy::Block => WindowsIpv6ResolvedPosture::Block,
            WindowsIpv6RequestedPolicy::Off => WindowsIpv6ResolvedPosture::Off,
        };
        Self {
            requested_policy,
            resolved_posture,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_runtime_state_preserves_the_apply_time_auto_resolution() {
        assert_eq!(
            WindowsIpv6RuntimeState::from_capture(WindowsIpv6RequestedPolicy::Auto, true)
                .resolved_posture,
            WindowsIpv6ResolvedPosture::Tunnel
        );
        assert_eq!(
            WindowsIpv6RuntimeState::from_capture(WindowsIpv6RequestedPolicy::Auto, false)
                .resolved_posture,
            WindowsIpv6ResolvedPosture::Block
        );
        assert_eq!(
            WindowsIpv6RuntimeState::from_capture(WindowsIpv6RequestedPolicy::Off, true)
                .resolved_posture,
            WindowsIpv6ResolvedPosture::Off
        );
    }
}
