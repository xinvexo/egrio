//! The Runtime's Core: reads, live updates, connection cutover and
//! quiescing, and the Core half of start, reload and stop.
use super::*;

impl Runtime {
    /// Returns this Runtime's in-process Core listener status. The Core is an
    /// instance resource: it is never shared through SDK assembly ports or a
    /// process-global coordinator.
    #[must_use]
    pub fn core_status(&self) -> egrio_core::NativeCoreStatus {
        self.core.status()
    }

    /// Bytes this Runtime's Core generation has relayed; `None` while no
    /// Core runs. A new generation starts again from zero.
    #[must_use]
    pub fn core_traffic_volume(&self) -> Option<egrio_core::TrafficVolume> {
        self.core.traffic_volume()
    }

    /// Returns telemetry from this Runtime's own Core generation.
    pub async fn core_traffic_telemetry_snapshot(&self) -> egrio_core::TrafficTelemetrySnapshot {
        self.core.traffic_telemetry_snapshot().await
    }

    /// [`Self::core_traffic_telemetry_snapshot`] with only the terminal
    /// records `cursor` has not seen, and the cursor for the next poll.
    pub async fn core_traffic_telemetry_since(
        &self,
        cursor: crate::TelemetryCursor,
    ) -> (egrio_core::TrafficTelemetrySnapshot, crate::TelemetryCursor) {
        self.core.traffic_telemetry_since(cursor).await
    }

    /// Evaluates the running Core's route without starting Core or a connection.
    pub async fn evaluate_core_route(
        &self,
        input: &egrio_core::RouteMatchInput,
    ) -> Result<Option<egrio_core::RouteEvaluation>, String> {
        let device = {
            let _operation = self.operation.lock().await;
            if self.status().state != RuntimeState::Running
                || self.core.status().state != egrio_core::NativeCoreState::Running
            {
                return Ok(None);
            }
            self.core.packet_device()
        };
        // A name an IP rule asks about waits on DNS; lifecycle operations do
        // not wait with it.
        match device {
            Some(device) => device.evaluate_route(input).await.map(Some),
            None => Ok(None),
        }
    }

    /// Requests `test_url` through the active Core's outbound `outbound` (a
    /// node or a group), as its health probes do, and records the outcome
    /// there. `None` while no Core runs, when the host probes standalone.
    pub async fn probe_outbound(
        &self,
        outbound: &str,
        test_url: &str,
    ) -> Result<Option<std::time::Duration>, String> {
        let device = {
            let _operation = self.operation.lock().await;
            let state = self.status().state;
            if self.core.status().state == egrio_core::NativeCoreState::Running {
                if !matches!(
                    state,
                    RuntimeState::Created | RuntimeState::Running | RuntimeState::Stopped
                ) {
                    return Err("outbound probe requires a settled running Runtime".into());
                }
                Some(
                    self.core
                        .packet_device()
                        .ok_or("running Core has no device")?,
                )
            } else if matches!(state, RuntimeState::Created | RuntimeState::Stopped) {
                None
            } else {
                return Err(
                    "outbound probe unavailable while Runtime requires transition or recovery"
                        .into(),
                );
            }
        };
        // As for endpoint probes, the operation lock is not held across I/O.
        match device {
            Some(device) => device.probe_outbound(outbound, test_url).await.map(Some),
            None => Ok(None),
        }
    }

    /// Invalidates the current Core's connections without replacing its device
    /// or the Runtime's platform resources.
    pub async fn cutover_core_sessions(
        &self,
    ) -> Result<egrio_core::ConnectionCutoverReport, String> {
        let _operation = self.operation.lock().await;
        self.configuration_update_admission()?;
        if !self.core_update_admission()? {
            return Ok(egrio_core::ConnectionCutoverReport::default());
        }
        let device = self.core.packet_device().expect("accepting Core device");
        device
            .cutover_sessions_and_wait(CORE_CONNECTION_CUTOVER_TIMEOUT)
            .await
    }

    /// Permanently closes this Core generation before a host attempts recovery.
    /// Platform restore failures must not allow the old data plane to continue.
    pub async fn quiesce_core(self: &Arc<Self>) -> Result<(), String> {
        let runtime = self.clone();
        self.spawn(async move { runtime.quiesce_core_transaction().await })
            .await
            .map_err(|error| error.to_string())?
    }

    pub(super) async fn quiesce_core_transaction(&self) -> Result<(), String> {
        let _operation = self.operation.lock().await;
        self.clear_session_loss();
        // Join the packet worker while its Core still accepts packet work.
        // Closing Core first races its UDP drain and can turn a normal stop
        // into a fatal "native core device is closed" report.
        let packet_stop = self.stop_packet_task().await;
        let core_drain = if let Some(device) = self.core.packet_device() {
            device.close();
            {
                let mut control = self.control.lock().expect("runtime control mutex");
                if !matches!(control.state, RuntimeState::Created | RuntimeState::Stopped) {
                    control.state = RuntimeState::Degraded;
                    control.degradation_error =
                        Some("Core generation was quiesced for recovery".into());
                }
            }
            device
                .cutover_sessions_and_wait(CORE_CONNECTION_CUTOVER_TIMEOUT)
                .await
                .map(|_| ())
        } else {
            Ok(())
        };
        // Core stays closed even when the packet stop failed. Preserve that
        // real failure; the caller still runs stop to restore OS resources.
        packet_stop.map_err(|error| error.to_string())?;
        core_drain
    }

    pub(super) fn core_update_admission(&self) -> Result<bool, String> {
        let state = self.status().state;
        let core = self.core.status();
        let device = self.core.packet_device();
        if matches!(state, RuntimeState::Created | RuntimeState::Stopped)
            && core.state == egrio_core::NativeCoreState::Stopped
            && device.is_none()
        {
            return Ok(false);
        }
        if state != RuntimeState::Running {
            return Err(format!(
                "Core update requires a Running Runtime, found {state:?}"
            ));
        }
        if core.state != egrio_core::NativeCoreState::Running
            || device.as_ref().is_none_or(|device| {
                device.status().state != egrio_core::NativeCoreDeviceState::Running
            })
        {
            return Err("Running Runtime has no accepting Core generation".into());
        }
        Ok(true)
    }

    /// Applies a profile and egress snapshot to this Runtime's live Core.
    pub async fn apply_core_with<F>(&self, load: F) -> Result<bool, String>
    where
        F: FnOnce() -> Result<
            (
                egrio_core::RuntimeProfile,
                egrio_core::NativeCoreEgressConfig,
            ),
            String,
        >,
    {
        let _operation = self.operation.lock().await;
        self.configuration_update_admission()?;
        if !self.core_update_admission()? {
            return Ok(false);
        }
        self.core.apply_with(load).await
    }

    /// Returns the live traffic projection of this Runtime's packet data
    /// plane: the raw device snapshot of the generation Core, which carries
    /// listener-relayed and packet-captured flows in one session registry. A
    /// snapshot is exposed only while the Runtime is committed `Running`;
    /// callers cannot accidentally present a prepared, degraded, or
    /// already-stopping Core as live.
    #[must_use]
    pub fn traffic_telemetry_snapshot(&self) -> Option<egrio_core::TrafficTelemetrySnapshot> {
        {
            let control = self.control.lock().expect("runtime control mutex");
            if control.state != RuntimeState::Running {
                return None;
            }
        }
        Some(self.core.packet_device()?.traffic_telemetry_snapshot())
    }

    /// The generation Core's bounded-state audit, for diagnostics hosts (the
    /// Windows validation harness). `None` while no generation Core runs.
    #[doc(hidden)]
    #[must_use]
    pub fn core_state_audit(&self) -> Option<egrio_core::CoreStateAudit> {
        Some(self.core.packet_device()?.state_audit())
    }

    /// One heartbeat diagnostic line from the generation Core, for
    /// diagnostics hosts. `None` while no generation Core runs.
    #[doc(hidden)]
    #[must_use]
    pub fn core_heartbeat_event(&self, event: &str, stalled_limit: usize) -> Option<String> {
        Some(
            self.core
                .packet_device()?
                .heartbeat_event(event, stalled_limit),
        )
    }

    pub(super) async fn rollback_prepared_core(
        &self,
        prepared: Option<PreparedRuntimeCore>,
        report: &mut RuntimeDomainReport,
    ) -> bool {
        if prepared.is_none() {
            return true;
        }
        let cleaned = self.abandon_start_core(prepared).await;
        report.push(RuntimeResourceChange::new(
            RuntimeResource::Core,
            if cleaned {
                RuntimeResourceOutcome::RolledBack
            } else {
                RuntimeResourceOutcome::RecoveryRequired
            },
        ));
        cleaned
    }

    pub(super) async fn stop_owned_core_after_restore(&self) -> Result<(), RuntimeStopError> {
        let active = self.control.lock().expect("runtime control mutex").core;
        let Some(active) = active else {
            return Ok(());
        };
        #[cfg(test)]
        if let Some(message) = self
            .core_stop_failure
            .lock()
            .expect("core stop failure mutex")
            .take()
        {
            let mut control = self.control.lock().expect("runtime control mutex");
            control.state = RuntimeState::Degraded;
            control.degradation_error = Some(message.clone());
            return Err(RuntimeStopError::Cleanup {
                message,
                capabilities_restored: true,
            });
        }
        match self.core.stop_generation(active).await {
            Ok(Some(_)) => {
                let mut control = self.control.lock().expect("runtime control mutex");
                if control.core == Some(active) {
                    control.core = None;
                }
                Ok(())
            }
            Ok(None) if self.core.status().state == egrio_core::NativeCoreState::Stopped => {
                let mut control = self.control.lock().expect("runtime control mutex");
                if control.core == Some(active) {
                    control.core = None;
                }
                Ok(())
            }
            Ok(None) => {
                let message = "Runtime Core generation changed before cleanup".to_string();
                let mut control = self.control.lock().expect("runtime control mutex");
                control.state = RuntimeState::Degraded;
                control.degradation_error = Some(message.clone());
                Err(RuntimeStopError::Cleanup {
                    message,
                    capabilities_restored: true,
                })
            }
            Err(message) => {
                let mut control = self.control.lock().expect("runtime control mutex");
                control.state = RuntimeState::Degraded;
                control.degradation_error = Some(message.clone());
                Err(RuntimeStopError::Cleanup {
                    message,
                    capabilities_restored: true,
                })
            }
        }
    }

    /// Starts the spec-declared Core and listener at the head of a start
    /// transaction. Returns the bound listener endpoint and the generation
    /// the transaction started, which it stops again if it does not commit;
    /// `Ok(None)` when the spec declares no Core.
    pub(super) async fn start_spec_core(
        &self,
        spec: &RuntimeSpec,
    ) -> Result<Option<PreparedRuntimeCore>, String> {
        let Some(core_spec) = spec.core.clone() else {
            return Ok(None);
        };
        let source = self
            .ports
            .core_config
            .as_ref()
            .expect("validated core config source")
            .clone();
        let report = self
            .core
            .ensure_with_listener(
                || {
                    let inputs = source.load()?;
                    if let Some(settings) = &spec.platform.packet_capture {
                        if inputs.capture.mtu != settings.mtu {
                            return Err(format!(
                                "Core packet MTU {} does not match requested capture MTU {}",
                                inputs.capture.mtu, settings.mtu
                            ));
                        }
                    }
                    Ok(inputs)
                },
                core_spec.listen_addr,
                core_spec.dns_listen_addr,
                core_spec.listen_port_fallback,
            )
            .await?;
        if !report.started_by_call {
            // A transaction starts a Core only where none runs: the Runtime
            // stops the generation it started before it is Created or
            // Stopped again, and a spec without a Core has none. One that
            // runs anyway is not this transaction's to use or to stop.
            return Err(
                "Runtime Core is already running outside this Runtime control state".into(),
            );
        }
        self.control.lock().expect("runtime control mutex").core = Some(report.generation);
        let listener = report
            .status
            .listen_addr
            .as_deref()
            .and_then(|value| value.parse::<SocketAddr>().ok());
        let started = PreparedRuntimeCore {
            listener: listener.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0))),
            generation: report.generation,
        };
        let mismatch = if listener.is_none() {
            Some("started Runtime Core reported no listener endpoint")
        } else if core_spec.listen_addr.is_some_and(|expected| {
            !listener_endpoint_matches(expected, started.listener)
                && !(core_spec.listen_port_fallback
                    && listener_falls_back_for(&report.status, expected, started.listener))
        }) {
            Some("running Runtime Core listener does not match the requested endpoint")
        } else if core_spec.dns_listen_addr.is_some_and(|expected| {
            report
                .status
                .dns_listen_addr
                .as_deref()
                .and_then(|value| value.parse::<SocketAddr>().ok())
                .is_none_or(|actual| !listener_endpoint_matches(expected, actual))
        }) {
            Some("running Runtime Core DNS listener does not match the requested endpoint")
        } else {
            None
        };
        if let Some(message) = mismatch {
            let _ = self.abandon_start_core(Some(started)).await;
            return Err(message.into());
        }
        Ok(Some(started))
    }

    pub(super) fn validate_packet_core_mtu(&self, spec: &RuntimeSpec) -> Result<(), String> {
        let Some(settings) = &spec.platform.packet_capture else {
            return Ok(());
        };
        let device = self
            .core
            .packet_device()
            .ok_or("packet capture requires the running Runtime Core")?;
        if device.capture_mtu() != settings.mtu {
            return Err(format!("Core packet MTU {} does not match requested capture MTU {}; rebuild the Core before capture", device.capture_mtu(), settings.mtu));
        }
        Ok(())
    }

    /// Stops the Core generation a failed start transaction created. Cleanup
    /// failures surface as a degradation note without masking the original
    /// start error.
    pub(super) async fn abandon_start_core(&self, started: Option<PreparedRuntimeCore>) -> bool {
        let Some(started) = started else {
            return true;
        };
        match self.core.stop_generation(started.generation).await {
            Ok(_) => {
                let mut control = self.control.lock().expect("runtime control mutex");
                if control.core == Some(started.generation) {
                    control.core = None;
                }
                true
            }
            Err(error) => {
                let mut control = self.control.lock().expect("runtime control mutex");
                control.state = RuntimeState::Degraded;
                control.degradation_error =
                    Some(format!("failed start left the Runtime Core dirty: {error}"));
                false
            }
        }
    }

    /// The listener endpoint bound by the running generation's Core, for
    /// resolving spec endpoints during reload.
    pub(super) fn core_listener_addr(&self) -> Option<SocketAddr> {
        self.core
            .status()
            .listen_addr
            .as_deref()
            .and_then(|value| value.parse().ok())
    }
}
