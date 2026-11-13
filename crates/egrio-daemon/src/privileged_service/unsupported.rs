use super::{PrivilegedServiceState, PrivilegedServiceStatus};

pub fn privileged_service_status() -> PrivilegedServiceStatus {
    PrivilegedServiceStatus {
        state: PrivilegedServiceState::NotInstalled,
        endpoint: None,
        detail: Some("this platform has no privileged service".into()),
    }
}
