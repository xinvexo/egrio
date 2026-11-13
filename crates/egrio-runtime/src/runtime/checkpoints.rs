//! Checkpoint persistence for the transactions, and recovery of an
//! unresolved checkpoint a previous process left.
use super::*;

impl Runtime {
    #[doc(hidden)]
    pub async fn recover_checkpoint(
        ports: RuntimePorts,
        lease_coordinator: Arc<dyn LeaseCoordinator>,
        checkpoint_store: Arc<dyn CheckpointStore>,
        grant: &LeaseGrant,
        mut stored: StoredCheckpoint,
    ) -> Result<RuntimeRecoveryReport, RuntimeRecoveryError> {
        lease_coordinator
            .begin_recovery(grant)
            .map_err(|error| RuntimeRecoveryError::Cleanup(error.to_string()))?;
        stored.checkpoint.operation = CheckpointOperation::Recover;
        stored.checkpoint.phase = CheckpointPhase::Restoring;
        stored = checkpoint_store
            .replace(stored.revision, stored.checkpoint.clone())
            .await
            .map_err(RuntimeRecoveryError::Store)?;

        for capability in stored.checkpoint.capabilities.clone().iter().rev() {
            let recovery_error = match restore_checkpoint(&ports, capability).await {
                Ok(report) if report.verified => continue,
                Ok(_) => {
                    RuntimeRecoveryError::Cleanup("capability recovery was not verified".into())
                }
                Err(error) => RuntimeRecoveryError::Capability(error),
            };
            stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
            let stored = checkpoint_store
                .replace(stored.revision, stored.checkpoint.clone())
                .await
                .unwrap_or(stored);
            let _ = lease_coordinator.mark_recovery_required(grant, stored.checkpoint.id);
            return Err(recovery_error);
        }
        checkpoint_store
            .delete(stored.checkpoint.id, stored.revision)
            .await
            .map_err(RuntimeRecoveryError::Store)?;
        lease_coordinator
            .release(grant, LeaseReleaseEvidence::VerifiedRestore)
            .map_err(|error| RuntimeRecoveryError::Cleanup(error.to_string()))?;
        Ok(RuntimeRecoveryReport {
            checkpoint_id: stored.checkpoint.id,
            restored: true,
            resources: RuntimeDomainReport::new(
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
            ),
        })
    }

    pub(super) async fn restore_original_checkpoint(
        &self,
        original: Option<&StoredCheckpoint>,
        transaction: Option<&StoredCheckpoint>,
    ) -> Result<Option<StoredCheckpoint>, CheckpointStoreError> {
        let Some(transaction) = transaction else {
            return Ok(original.cloned());
        };
        if let Some(original) = original {
            self.checkpoint_store
                .replace(transaction.revision, original.checkpoint.clone())
                .await
                .map(Some)
        } else {
            self.checkpoint_store
                .delete(transaction.checkpoint.id, transaction.revision)
                .await?;
            Ok(None)
        }
    }

    pub(super) async fn persist_checkpoint(
        &self,
        stored: &StoredCheckpoint,
    ) -> Result<StoredCheckpoint, CheckpointStoreError> {
        match self
            .checkpoint_store
            .replace(stored.revision, stored.checkpoint.clone())
            .await
        {
            Ok(value) => Ok(value),
            Err(error) if error.code == CheckpointStoreErrorCode::NotFound => {
                self.checkpoint_store
                    .create(stored.checkpoint.clone())
                    .await
            }
            Err(error) => Err(error),
        }
    }

    pub(super) async fn delete_checkpoint_if_present(
        &self,
        stored: &StoredCheckpoint,
    ) -> Result<(), CheckpointStoreError> {
        match self
            .checkpoint_store
            .delete(stored.checkpoint.id, stored.revision)
            .await
        {
            Ok(()) => Ok(()),
            Err(error) if error.code == CheckpointStoreErrorCode::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(super) async fn recreate_deleted_checkpoint(
        &self,
        mut stored: StoredCheckpoint,
    ) -> (StoredCheckpoint, Option<CheckpointStoreError>) {
        stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
        match self
            .checkpoint_store
            .create(stored.checkpoint.clone())
            .await
        {
            Ok(value) => (value, None),
            Err(error) => (stored, Some(error)),
        }
    }

    pub(super) async fn restore_capability(
        &self,
        checkpoint: &CapabilityCheckpoint,
    ) -> Result<CapabilityOperationReport, CapabilityError> {
        if checkpoint.lease_key == PlatformLeaseKey::packet_capture() {
            self.stop_packet_task().await?;
        }
        restore_checkpoint(&self.ports, checkpoint).await
    }

    pub(super) fn retain_recovery(
        &self,
        grant: Option<LeaseGrant>,
        mut checkpoint: StoredCheckpoint,
    ) {
        checkpoint.checkpoint.phase = CheckpointPhase::RecoveryRequired;
        if let Some(value) = grant.as_ref() {
            let _ = self
                .lease_coordinator
                .mark_recovery_required(value, checkpoint.checkpoint.id);
        }
        let mut control = self.control.lock().expect("runtime control mutex");
        control.state = RuntimeState::Degraded;
        control.lease_grant = grant;
        control.checkpoint = Some(checkpoint);
    }
}
