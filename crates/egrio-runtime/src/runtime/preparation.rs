//! Preparing one generation's outbounds before its ordinary ingress opens.
use super::*;

impl Runtime {
    /// Prepares the Core declared by `spec`, leaving every listener and
    /// platform capability off. Repeating it updates the requested topology.
    pub async fn prepare_core(
        self: &Arc<Self>,
        spec: RuntimeSpec,
    ) -> Result<RuntimeCoreGeneration, String> {
        let runtime = self.clone();
        self.spawn(async move {
            let _operation = runtime.operation.lock().await;
            spec.validate().map_err(|error| error.to_string())?;
            if spec.id != runtime.id() || spec.core.is_none() {
                return Err("Core preparation requires this Runtime's Core spec".into());
            }
            validate_ports(&spec, &runtime.ports).map_err(|error| error.to_string())?;
            if !matches!(
                runtime.status().state,
                RuntimeState::Created | RuntimeState::Stopped | RuntimeState::Preparing
            ) {
                return Err("Core preparation requires a stopped or preparing Runtime".into());
            }
            let source = runtime
                .ports
                .core_config
                .as_ref()
                .expect("validated Core source");
            let generation = runtime.core.prepare_with(|| source.load()).await?;
            let mut control = runtime.control.lock().expect("runtime control mutex");
            control.core = Some(generation);
            control.spec = spec;
            control.state = RuntimeState::Preparing;
            control.degradation_error = None;
            Ok(generation)
        })
        .await
        .map_err(|error| error.to_string())?
    }

    /// Publishes the final profile and activates this same prepared generation.
    pub async fn activate_prepared_core(
        self: &Arc<Self>,
        generation: RuntimeCoreGeneration,
        profile: egrio_core::RuntimeProfile,
    ) -> Result<RuntimeStartReport, RuntimeStartError> {
        let runtime = self.clone();
        self.spawn(async move {
            let report = runtime
                .start_transaction(None, Some((generation, profile)))
                .await?;
            runtime.sync_health_watcher().await;
            Ok(report)
        })
        .await
        .map_err(|error| RuntimeStartError::Task(error.to_string()))?
    }

    /// The failure of host preparation, retained without opening any ingress.
    pub fn core_preparation_failed(&self, generation: RuntimeCoreGeneration, error: String) {
        let mut control = self.control.lock().expect("runtime control mutex");
        if control.state == RuntimeState::Preparing && control.core == Some(generation) {
            control.degradation_error = Some(error);
        }
    }

    /// Opens a host-originated stream using the current Core and its selection.
    /// Network I/O runs without holding the lifecycle operation lock.
    pub async fn connect_outbound(
        &self,
        outbound: Option<&str>,
        host: &str,
        port: u16,
    ) -> Result<egrio_core::CoreOutboundStream, String> {
        let device = {
            let _operation = self.operation.lock().await;
            self.core_update_admission()?;
            self.core
                .packet_device()
                .ok_or("Runtime has no active Core")?
        };
        device.connect_outbound(outbound, host, port).await
    }
}
