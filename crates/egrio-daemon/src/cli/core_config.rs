use std::fs;
use std::net::SocketAddr;
use std::path::Path;

use egrio_core::{NativeCoreCaptureConfig, NativeCoreEgressConfig, RuntimeProfile};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RuntimeConfig {
    pub(super) profile: RuntimeProfile,
    #[serde(default)]
    pub(super) egress: NativeCoreEgressConfig,
    #[serde(default)]
    pub(super) capture: NativeCoreCaptureConfig,
    #[serde(default)]
    pub(super) listen_addr: Option<SocketAddr>,
    #[serde(default)]
    pub(super) dns_listen_addr: Option<SocketAddr>,
}

impl RuntimeConfig {
    pub(super) fn from_profile(profile: RuntimeProfile) -> Self {
        Self {
            profile,
            egress: NativeCoreEgressConfig::default(),
            capture: NativeCoreCaptureConfig::default(),
            listen_addr: None,
            dns_listen_addr: None,
        }
    }
}

pub(super) fn load_config(path: impl AsRef<Path>) -> Result<RuntimeConfig, String> {
    let path = path.as_ref();
    let path_label = path.display().to_string();
    let document = fs::read_to_string(path)
        .map_err(|error| format!("failed to read runtime config {path_label}: {error}"))?;

    match path.extension().and_then(|extension| extension.to_str()) {
        Some("yaml") | Some("yml") => serde_yaml::from_str(&document)
            .map_err(|error| format!("failed to parse runtime config {path_label}: {error}")),
        _ => serde_json::from_str(&document)
            .map_err(|error| format!("failed to parse runtime config {path_label}: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use uuid::Uuid;

    #[test]
    fn runtime_config_loads_from_json_file() {
        let path = write_runtime_config("json", |config| {
            serde_json::to_string(config).expect("serialize runtime config")
        });

        let config = load_config(&path).expect("runtime config should load");

        assert_eq!(config.profile.name, "runtime-config-file");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn runtime_config_loads_from_yaml_file() {
        let path = write_runtime_config("yaml", |config| {
            serde_yaml::to_string(config).expect("serialize runtime config")
        });

        let config = load_config(&path).expect("runtime config should load");

        assert_eq!(config.profile.name, "runtime-config-file");
        let _ = fs::remove_file(path);
    }

    fn write_runtime_config(
        extension: &str,
        serialize: impl FnOnce(&RuntimeConfig) -> String,
    ) -> PathBuf {
        let config = RuntimeConfig::from_profile(RuntimeProfile::new("runtime-config-file"));
        let path = std::env::temp_dir().join(format!(
            "egrio-runtime-config-{}.{}",
            Uuid::new_v4(),
            extension
        ));
        fs::write(&path, serialize(&config)).expect("write runtime config");
        path
    }
}
