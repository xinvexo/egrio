mod bootstrap;
mod checkpoint;
mod core_executor;
mod file_checkpoint;
mod lease;
#[cfg(all(feature = "platform-macos", target_os = "macos"))]
mod macos_service;
mod memory_platform;
mod native_packet_data_plane;

#[cfg(feature = "platform-linux")]
pub use bootstrap::LinuxServiceConfig;
#[cfg(feature = "platform-macos")]
pub use bootstrap::MacosServiceConfig;
#[cfg(feature = "platform-windows")]
pub use bootstrap::WindowsServiceConfig;
pub use bootstrap::{
    EgrioSdk, EgrioSdkBuilder, RecoveryBootstrapError, RecoveryBootstrapReport, RuntimeCreateError,
    RuntimeRemoveError, SdkBuildError, SdkBuildErrorCode,
};
pub use checkpoint::InMemoryCheckpointStore;
pub use egrio_runtime::{RuntimeGeneration, RuntimeId, RuntimeState};
/// The Core egress guard that pairs with [`EgrioSdkBuilder::linux_service`].
#[cfg(all(feature = "platform-linux", target_os = "linux"))]
pub use egrio_service::linux::ServiceMarkingSocketGuard;
pub use file_checkpoint::FileCheckpointStore;
pub use lease::{PlatformLeaseCoordinator, PlatformLeaseStatus, RecoveryReservationError};
#[cfg(all(feature = "platform-macos", target_os = "macos"))]
pub use macos_service::{macos_service_hello, MacosServiceHello};
pub use memory_platform::InMemoryPlatform;
pub use native_packet_data_plane::NativeCorePacketDataPlane;
