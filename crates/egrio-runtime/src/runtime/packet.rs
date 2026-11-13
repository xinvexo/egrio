//! The packet data plane task: start, stop, exit reports, and degradation
//! when it exits on its own.
use super::*;

#[derive(Debug, Default)]
pub(super) struct PacketReportState {
    pub(super) published: Option<TaskId>,
    pub(super) report: Option<egrio_core::NativeCoreDeviceRunReport>,
}

#[derive(Debug)]
pub(super) struct ActivePacketTask {
    pub(super) settings: PacketCaptureSettings,
    pub(super) stop: CancellationToken,
    pub(super) worker: ManagedTask<egrio_core::NativeCoreDeviceRunReport>,
}

impl Runtime {
    /// The latest completed data-plane report, including failures. It is
    /// available before stop; taking it consumes this task's report once.
    #[must_use]
    pub fn take_packet_report(&self) -> Option<egrio_core::NativeCoreDeviceRunReport> {
        // The completion fact is readable even if its lifecycle notification
        // is waiting for an in-progress start/stop transaction.
        {
            let task = self.packet_task.lock().expect("packet task mutex");
            if let Some(active) = task.as_ref() {
                if let Some(completion) = active.worker.completion() {
                    self.record_packet_report(active.worker.id(), &completion);
                }
            }
        }
        self.packet_report
            .lock()
            .expect("packet report mutex")
            .report
            .take()
    }

    pub(super) fn completed_task_error(&self) -> Option<CapabilityError> {
        if let Some(completion) = self
            .packet_task
            .lock()
            .expect("packet task mutex")
            .as_ref()
            .and_then(|task| task.worker.completion())
        {
            return Some(packet_capability_error(
                crate::CapabilityErrorCode::ApplyFailed,
                packet_exit_message(&completion),
            ));
        }
        None
    }

    pub(super) fn record_packet_report(
        &self,
        id: TaskId,
        completion: &Completion<egrio_core::NativeCoreDeviceRunReport>,
    ) {
        let mut state = self.packet_report.lock().expect("packet report mutex");
        if state.published != Some(id) {
            state.published = Some(id);
            state.report = Some(packet_run_report(completion));
        }
    }

    pub(super) fn notify_task_exit(self: &Arc<Self>, task_id: TaskId) {
        // Completion callbacks never wait for operation: stop/reload can hold
        // it while awaiting the worker's join. The exact worker identity fences
        // notifications queued before a replacement or removal.
        let runtime = Arc::downgrade(self);
        drop(self.spawn(async move {
            if let Some(runtime) = runtime.upgrade() {
                runtime.degrade_after_task_exit(task_id).await;
            }
        }));
    }

    /// A packet data plane only ends on its own when the session behind it
    /// (the service, or the OS tunnel) did, so its exit is a session loss.
    pub(super) async fn degrade_after_task_exit(&self, task_id: TaskId) {
        let _operation = self.operation.lock().await;
        let message = {
            let tasks = self.packet_task.lock().expect("packet task mutex");
            let Some(active) = tasks.as_ref().filter(|task| task.worker.id() == task_id) else {
                return;
            };
            let Some(completion) = active.worker.completion() else {
                return;
            };
            self.record_packet_report(task_id, &completion);
            if completion.expected_stop {
                return;
            }
            packet_exit_message(&completion)
        };
        let (stored, mut errors) = {
            let mut control = self.control.lock().expect("runtime control mutex");
            if control.state != RuntimeState::Running {
                return;
            }
            control.state = RuntimeState::Degraded;
            control.session_lost = true;
            control.degradation_error = Some(message.clone());
            let mut errors = vec![message];
            if let (Some(grant), Some(stored)) =
                (control.lease_grant.as_ref(), control.checkpoint.as_ref())
            {
                if let Err(error) = self
                    .lease_coordinator
                    .mark_recovery_required(grant, stored.checkpoint.id)
                {
                    errors.push(error.to_string());
                }
            }
            (control.checkpoint.clone(), errors)
        };
        if let Some(mut stored) = stored {
            stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
            match self
                .checkpoint_store
                .replace(stored.revision, stored.checkpoint.clone())
                .await
            {
                Ok(replaced) => stored = replaced,
                Err(error) => errors.push(error.to_string()),
            }
            self.control
                .lock()
                .expect("runtime control mutex")
                .checkpoint = Some(stored);
        }
        self.control
            .lock()
            .expect("runtime control mutex")
            .degradation_error = Some(errors.join("; "));
        self.session_loss
            .send_modify(|losses| *losses = losses.wrapping_add(1));
    }

    pub(super) async fn start_packet_capture(
        self: &Arc<Self>,
        settings: &PacketCaptureSettings,
    ) -> Result<CapabilityOperationReport, CapabilityError> {
        {
            let task = self.packet_task.lock().expect("packet task mutex");
            if let Some(active) = task.as_ref() {
                if let Some(completion) = active.worker.completion() {
                    return Err(packet_capability_error(
                        crate::CapabilityErrorCode::ApplyFailed,
                        packet_exit_message(&completion),
                    ));
                }
                if active.settings == *settings {
                    return Ok(CapabilityOperationReport {
                        capability: CapabilityKind::PacketCapture,
                        changed: false,
                        verified: true,
                    });
                }
                return Err(packet_capability_error(
                    crate::CapabilityErrorCode::InvalidRequest,
                    "packet capture settings cannot change while its data plane is active",
                ));
            }
        }
        // A queue per executor at most, each queue's pump on its own.
        let executors = match self.executors.as_slice() {
            [] => vec![tokio::runtime::Handle::current()],
            executors => executors.to_vec(),
        };
        let opened = self
            .ports
            .packet_capture
            .as_ref()
            .expect("validated packet capture port")
            .open(settings, executors.len())
            .await?;
        if opened.queues.is_empty() || opened.queues.len() > executors.len() {
            return Err(packet_capability_error(
                crate::CapabilityErrorCode::ApplyFailed,
                format!(
                    "packet capture opened {} queues for {} executors",
                    opened.queues.len(),
                    executors.len()
                ),
            ));
        }
        let core = self.core.packet_device().ok_or_else(|| {
            packet_capability_error(
                crate::CapabilityErrorCode::ApplyFailed,
                "packet capture requires the running Runtime Core",
            )
        })?;
        let stop = CancellationToken::new();
        let open_report = opened.report.clone();
        let queues = opened.queues.into_iter().zip(executors).collect();
        let future = self
            .ports
            .packet_data_plane
            .as_ref()
            .expect("validated packet data plane")
            .run(core, queues, stop.clone());
        let runtime = Arc::downgrade(self);
        let mut worker = ManagedTask::spawn(self.executor(), future, move |task_id| {
            if let Some(runtime) = runtime.upgrade() {
                runtime.notify_task_exit(task_id);
            }
        });
        worker.started().await.map_err(|error| {
            packet_capability_error(crate::CapabilityErrorCode::ApplyFailed, error)
        })?;
        let startup_completion = worker.completion();
        let task_id = worker.id();
        {
            let mut task = self.packet_task.lock().expect("packet task mutex");
            *task = Some(ActivePacketTask {
                settings: settings.clone(),
                stop,
                worker,
            });
        }
        if let Some(completion) = startup_completion {
            self.record_packet_report(task_id, &completion);
            return Err(packet_capability_error(
                crate::CapabilityErrorCode::ApplyFailed,
                format!(
                    "packet data plane failed during startup: {}",
                    packet_exit_message(&completion)
                ),
            ));
        }
        Ok(open_report)
    }

    /// Moves the open capture to `settings`, which differ from its own only
    /// in the excluded prefixes; the device and its packet task stay.
    pub(super) async fn update_packet_capture(
        &self,
        settings: &PacketCaptureSettings,
    ) -> Result<CapabilityOperationReport, CapabilityError> {
        {
            let mut task = self.packet_task.lock().expect("packet task mutex");
            let Some(active) = task.as_mut() else {
                return Err(packet_capability_error(
                    crate::CapabilityErrorCode::InvalidRequest,
                    "no open packet capture to update",
                ));
            };
            if active.settings == *settings {
                return Ok(CapabilityOperationReport {
                    capability: CapabilityKind::PacketCapture,
                    changed: false,
                    verified: true,
                });
            }
            if !active.settings.differs_only_in_exclusions(settings) {
                return Err(packet_capability_error(
                    crate::CapabilityErrorCode::InvalidRequest,
                    "an open packet capture changes only its exclusions",
                ));
            }
            // Recorded before the adapter runs: after a failure the session
            // may hold either list, so the undo must send its own again.
            active.settings = settings.clone();
        }
        self.ports
            .packet_capture
            .as_ref()
            .expect("validated packet capture port")
            .update_excluded_prefixes(&settings.excluded_prefixes)
            .await
    }

    pub(super) async fn stop_packet_task(&self) -> Result<(), CapabilityError> {
        let active = self.packet_task.lock().expect("packet task mutex").take();
        let Some(mut active) = active else {
            return Ok(());
        };
        let already_completed = active.worker.completion().is_some();
        active.worker.request_stop();
        active.stop.cancel();
        let completion =
            match tokio::time::timeout(PACKET_TASK_STOP_TIMEOUT, active.worker.join()).await {
                Ok(Ok(completion)) => completion,
                Ok(Err(error)) => {
                    return Err(packet_capability_error(
                        crate::CapabilityErrorCode::RestoreFailed,
                        error,
                    ))
                }
                Err(_) => {
                    // Retain the worker until a later stop can verify exit;
                    // never detach an aborted worker and claim that capture
                    // resources were released.
                    *self.packet_task.lock().expect("packet task mutex") = Some(active);
                    return Err(packet_capability_error(
                        crate::CapabilityErrorCode::RestoreFailed,
                        format!(
                            "packet data plane did not stop within {}s of cancellation",
                            PACKET_TASK_STOP_TIMEOUT.as_secs()
                        ),
                    ));
                }
            };
        let report = packet_run_report(&completion);
        let failure = report.fatal_error.clone();
        self.record_packet_report(active.worker.id(), &completion);
        // A recorded running failure remains a failure in the report/Runtime
        // history, but an already-exited worker cannot block OS restoration.
        if already_completed || !completion.expected_stop {
            return Ok(());
        }
        failure.map_or(Ok(()), |error| {
            Err(packet_capability_error(
                crate::CapabilityErrorCode::RestoreFailed,
                error,
            ))
        })
    }
}

pub(super) fn packet_capability_error(
    code: crate::CapabilityErrorCode,
    message: impl Into<String>,
) -> CapabilityError {
    CapabilityError::new(CapabilityKind::PacketCapture, code, message)
}

pub(super) fn packet_run_report(
    completion: &Completion<egrio_core::NativeCoreDeviceRunReport>,
) -> egrio_core::NativeCoreDeviceRunReport {
    match &completion.result {
        Ok(report) => report.clone(),
        Err(error) => egrio_core::NativeCoreDeviceRunReport {
            shutdown_requested: completion.expected_stop,
            last_error: Some(error.to_string()),
            fatal_error: Some(error.to_string()),
            ..Default::default()
        },
    }
}

pub(super) fn packet_exit_message(
    completion: &Completion<egrio_core::NativeCoreDeviceRunReport>,
) -> String {
    let report = packet_run_report(completion);
    report
        .fatal_error
        .unwrap_or_else(|| "packet data plane exited while the Runtime was running".into())
}
