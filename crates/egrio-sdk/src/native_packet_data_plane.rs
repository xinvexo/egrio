use egrio_core::{NativeCoreDevice, PacketDevice};
use egrio_runtime::{PacketDataPlane, PacketDataPlaneFuture};
use tokio_util::sync::CancellationToken;

/// Drives the capture device against the Runtime-owned generation Core. The
/// plane is stateless: the Core arrives per run from the Runtime, so this
/// adapter cannot privately hold, replace, or hot-apply a second Core — the
/// listener session and the packet pump share the generation Core by
/// construction.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeCorePacketDataPlane;

impl PacketDataPlane for NativeCorePacketDataPlane {
    fn run(
        &self,
        core: NativeCoreDevice,
        queues: Vec<(Box<dyn PacketDevice>, tokio::runtime::Handle)>,
        stop: CancellationToken,
    ) -> PacketDataPlaneFuture {
        Box::pin(async move { Ok(core.run_packet_queues(queues, stop).await) })
    }
}
