use std::sync::Arc;

use egrio_runtime::{CheckpointStore, PacketDataPlane, PacketDataPlaneFuture, RuntimeState};
use egrio_sdk::{EgrioSdk, InMemoryCheckpointStore, InMemoryPlatform, NativeCorePacketDataPlane};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::{packet_spec, FatalAtTeardownDataPlane, TestCoreConfig};

#[tokio::test]
async fn quiescing_capture_joins_the_packet_pump_before_closing_core() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(Arc::new(InMemoryPlatform::new()))
        .packet_data_plane(Arc::new(NativeCorePacketDataPlane))
        .core_config(Arc::new(TestCoreConfig("quiesce-capture")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();

    runtime.quiesce_core().await.unwrap();
    let report = runtime
        .take_packet_report()
        .expect("quiesce joins and records the packet task before closing Core");
    assert!(report.shutdown_requested);
    assert_eq!(report.fatal_error, None);

    runtime
        .stop()
        .await
        .expect("quiesced capture restores cleanly");
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[tokio::test]
async fn quiescing_capture_preserves_a_real_packet_failure_during_stop() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(Arc::new(InMemoryPlatform::new()))
        .packet_data_plane(Arc::new(FatalAtTeardownDataPlane))
        .core_config(Arc::new(TestCoreConfig("quiesce-capture-failure")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();

    let error = runtime
        .quiesce_core()
        .await
        .expect_err("quiesce must report a real device failure during stop");
    assert!(error.contains("shared packet ring failed: Cancelled"));
    let report = runtime
        .take_packet_report()
        .expect("failure report is retained");
    assert_eq!(report.packets_received, 42);
    assert_eq!(
        report.fatal_error.as_deref(),
        Some("shared packet ring failed: Cancelled")
    );
    assert!(runtime
        .apply_core_with(|| panic!("failed quiesce must leave Core closed"))
        .await
        .is_err());

    // Once recorded, the exited worker must not prevent verified OS restore.
    runtime.stop().await.unwrap();
    assert!(store.list_unresolved().await.unwrap().is_empty());
}

#[derive(Debug, Default)]
struct PausedPacketStop {
    stopping: Arc<Notify>,
    release: Arc<Notify>,
}

impl PacketDataPlane for PausedPacketStop {
    fn run(
        &self,
        _core: egrio_core::NativeCoreDevice,
        queues: Vec<(Box<dyn egrio_core::PacketDevice>, tokio::runtime::Handle)>,
        stop: CancellationToken,
    ) -> PacketDataPlaneFuture {
        let stopping = self.stopping.clone();
        let release = self.release.clone();
        Box::pin(async move {
            let _queues = queues;
            stop.cancelled().await;
            stopping.notify_one();
            release.notified().await;
            Ok(egrio_core::NativeCoreDeviceRunReport {
                shutdown_requested: true,
                ..Default::default()
            })
        })
    }
}

#[tokio::test]
async fn cancelling_the_quiesce_caller_keeps_packet_join_and_core_close_owned() {
    let store = Arc::new(InMemoryCheckpointStore::new());
    let packet = Arc::new(PausedPacketStop::default());
    let sdk = EgrioSdk::builder()
        .checkpoint_store(store.clone())
        .platform(Arc::new(InMemoryPlatform::new()))
        .packet_data_plane(packet.clone())
        .core_config(Arc::new(TestCoreConfig("cancel-quiesce-caller")))
        .build()
        .unwrap();
    let runtime = sdk.create_runtime(packet_spec()).await.unwrap();
    runtime.start().await.unwrap();

    let caller = tokio::spawn({
        let runtime = runtime.clone();
        async move { runtime.quiesce_core().await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        packet.stopping.notified(),
    )
    .await
    .expect("quiesce requests packet stop");
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    packet.release.notify_one();

    runtime.stop().await.unwrap();
    let report = runtime
        .take_packet_report()
        .expect("packet join survives caller cancellation");
    assert!(report.shutdown_requested);
    assert_eq!(report.fatal_error, None);
    assert!(store.list_unresolved().await.unwrap().is_empty());
}
