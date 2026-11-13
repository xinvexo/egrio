//! Node latency tests. With the profile running, the Core's own probe (which
//! also feeds its health); otherwise a standalone probe over the host's
//! physical egress, compiling no Core.
use egrio_core::RuntimeProfile;

use super::{DesktopHost, DesktopRuntime};

impl<H: DesktopHost> DesktopRuntime<H> {
    pub(crate) async fn probe_node(
        &self,
        profile: RuntimeProfile,
        node: &str,
        test_url: &str,
    ) -> Result<u32, String> {
        if self.running_profile_id().as_deref() == Some(profile.id.as_str()) {
            if let Some(runtime) = self.existing_desktop_runtime() {
                if let Some(elapsed) = runtime.probe_outbound(node, test_url).await? {
                    return Ok(milliseconds(elapsed));
                }
            }
        }
        // Protection is also prepared before capture starts, so enabling TUN
        // cannot recapture a standalone probe that is already in progress.
        let (egress, socket_guard) = self.host.standalone_probe_egress().await?;
        let elapsed =
            egrio_core::probe_profile_node(profile, node, test_url, egress, socket_guard).await?;
        Ok(milliseconds(elapsed))
    }
}

fn milliseconds(elapsed: std::time::Duration) -> u32 {
    elapsed.as_millis().min(u128::from(u32::MAX)) as u32
}
