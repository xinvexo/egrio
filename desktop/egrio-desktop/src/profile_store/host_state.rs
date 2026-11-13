use super::*;

impl ProfileStore {
    pub fn app_setting(&self, key: &str) -> Result<Option<String>, ProfileStoreError> {
        Ok(self.load()?.app_settings.get(key).cloned())
    }
    pub fn set_app_setting(&self, key: &str, value: &str) -> Result<(), ProfileStoreError> {
        if matches!(key, "ipv6_enabled" | "allow_lan" | "mixed_port")
            || key.starts_with("group-selection:")
        {
            return Err(ProfileStoreError::Configuration(
                "network configuration belongs to a Profile".into(),
            ));
        }
        self.write(|doc| {
            doc.app_settings.insert(key.into(), value.into());
            Ok(())
        })
    }
}
