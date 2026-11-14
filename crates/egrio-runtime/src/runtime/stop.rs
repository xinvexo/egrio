//! The stop transaction: restore every capability in reverse order, then
//! stop the Core and release the leases.
use super::*;

impl Runtime {
    pub async fn stop(self: &Arc<Self>) -> Result<RuntimeStopReport, RuntimeStopError> {
        let runtime = self.clone();
        self.spawn(async move { runtime.stop_transaction().await })
            .await
            .map_err(|error| RuntimeStopError::Task(error.to_string()))?
    }

    pub(super) async fn stop_transaction(&self) -> Result<RuntimeStopReport, RuntimeStopError> {
        let _operation = self.operation.lock().await;
        self.clear_session_loss();
        let _configuration_stop = configuration::ConfigurationStopCompletion(self);
        self.cancel_health_watcher();
        let (initial_state, had_core) = {
            let control = self.control.lock().expect("runtime control mutex");
            (control.state, control.core.is_some())
        };
        if initial_state == RuntimeState::Stopped {
            self.stop_owned_core_after_restore().await?;
            return Ok(RuntimeStopReport {
                generation: self.status().generation,
                changed: false,
                restored: true,
                resources: RuntimeDomainReport::default(),
            });
        }
        if matches!(
            initial_state,
            RuntimeState::Created | RuntimeState::Preparing
        ) {
            self.stop_owned_core_after_restore().await?;
            let mut control = self.control.lock().expect("runtime control mutex");
            control.state = RuntimeState::Stopped;
            let resources = had_core
                .then(|| {
                    RuntimeResourceChange::new(
                        RuntimeResource::Core,
                        RuntimeResourceOutcome::Restored,
                    )
                })
                .into_iter()
                .collect();
            return Ok(RuntimeStopReport {
                generation: control.generation,
                changed: true,
                restored: true,
                resources: RuntimeDomainReport::new(resources),
            });
        }
        let (previous_state, mut grant, stored, generation) = {
            let mut control = self.control.lock().expect("runtime control mutex");
            if control.state != RuntimeState::Running && control.state != RuntimeState::Degraded {
                return Err(RuntimeStopError::InvalidState(control.state));
            }
            let previous_state = control.state;
            control.state = RuntimeState::Stopping;
            (
                previous_state,
                control.lease_grant.take(),
                control.checkpoint.take(),
                control.generation,
            )
        };

        let Some(mut stored) = stored else {
            if let Err(error) = self.stop_owned_core_after_restore().await {
                self.control
                    .lock()
                    .expect("runtime control mutex")
                    .lease_grant = grant;
                return Err(error);
            }
            if let Some(value) = grant.take() {
                if let Err(error) = self
                    .lease_coordinator
                    .release(&value, LeaseReleaseEvidence::NoModification)
                {
                    let mut control = self.control.lock().expect("runtime control mutex");
                    control.state = RuntimeState::Degraded;
                    control.lease_grant = Some(value);
                    control.degradation_error = Some(error.to_string());
                    return Err(RuntimeStopError::Cleanup {
                        message: error.to_string(),
                        capabilities_restored: true,
                    });
                }
            }
            self.set_state(RuntimeState::Stopped);
            let resources = had_core
                .then(|| {
                    RuntimeResourceChange::new(
                        RuntimeResource::Core,
                        RuntimeResourceOutcome::Restored,
                    )
                })
                .into_iter()
                .collect();
            return Ok(RuntimeStopReport {
                generation,
                changed: true,
                restored: true,
                resources: RuntimeDomainReport::new(resources),
            });
        };

        let mut resources = RuntimeDomainReport::new(
            stored
                .checkpoint
                .capabilities
                .iter()
                .map(|capability| {
                    RuntimeResourceChange::new(
                        resource_for_key(&capability.lease_key),
                        RuntimeResourceOutcome::Restored,
                    )
                })
                .collect(),
        );

        let recovering_platform = previous_state == RuntimeState::Degraded
            && stored.checkpoint.phase == CheckpointPhase::RecoveryRequired;
        if recovering_platform {
            if let Some(value) = grant.as_ref() {
                if let Err(error) = self.lease_coordinator.begin_recovery(value) {
                    self.retain_recovery(grant, stored);
                    return Err(RuntimeStopError::Cleanup {
                        message: error.to_string(),
                        capabilities_restored: false,
                    });
                }
            }
        }

        for capability in stored.checkpoint.capabilities.clone().iter().rev() {
            match self.restore_capability(capability).await {
                Ok(report) if report.verified => {}
                Ok(_) => {
                    self.retain_recovery(grant, stored);
                    return Err(RuntimeStopError::Cleanup {
                        message: "capability restore was not verified".into(),
                        capabilities_restored: false,
                    });
                }
                Err(error) => {
                    stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
                    if let Ok(value) = self.persist_checkpoint(&stored).await {
                        stored = value;
                    }
                    self.retain_recovery(grant, stored);
                    return Err(RuntimeStopError::Capability(error));
                }
            }
        }

        if let Err(error) = self.stop_owned_core_after_restore().await {
            self.retain_recovery(grant, stored);
            return Err(error);
        }

        if let Some(value) = grant.take() {
            let transition = if recovering_platform {
                Ok(())
            } else {
                self.lease_coordinator.begin_release(&value)
            };
            if let Err(error) = transition {
                self.retain_recovery(Some(value), stored);
                return Err(RuntimeStopError::Cleanup {
                    message: error.to_string(),
                    capabilities_restored: true,
                });
            }
            if let Err(error) = self.delete_checkpoint_if_present(&stored).await {
                self.retain_recovery(Some(value), stored);
                return Err(RuntimeStopError::Store(error));
            }
            if let Err(error) = self
                .lease_coordinator
                .release(&value, LeaseReleaseEvidence::VerifiedRestore)
            {
                let message = error.to_string();
                let (stored, store_error) = self.recreate_deleted_checkpoint(stored).await;
                self.retain_recovery(Some(value), stored);
                return Err(RuntimeStopError::Cleanup {
                    message: store_error.map_or(message.clone(), |store_error| {
                        format!("{message}; failed to recreate recovery checkpoint: {store_error}")
                    }),
                    capabilities_restored: true,
                });
            }
        } else if let Err(error) = self.delete_checkpoint_if_present(&stored).await {
            self.retain_recovery(None, stored);
            return Err(RuntimeStopError::Store(error));
        }
        if had_core {
            resources.push(RuntimeResourceChange::new(
                RuntimeResource::Core,
                RuntimeResourceOutcome::Restored,
            ));
        }
        let mut control = self.control.lock().expect("runtime control mutex");
        control.state = RuntimeState::Stopped;
        control.degradation_error = None;
        Ok(RuntimeStopReport {
            generation: control.generation,
            changed: true,
            restored: true,
            resources,
        })
    }
}
