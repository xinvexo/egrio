//! The reload transaction: move a running Runtime to a new spec in place,
//! keeping the Core and unchanged capabilities, and compensate a failure
//! back to the committed spec.
use super::*;

impl Runtime {
    pub async fn reload(
        self: &Arc<Self>,
        next_spec: RuntimeSpec,
    ) -> Result<RuntimeReloadReport, RuntimeReloadError> {
        let runtime = self.clone();
        self.spawn(async move {
            let report = runtime.reload_transaction(next_spec).await?;
            runtime.sync_health_watcher().await;
            Ok(report)
        })
        .await
        .map_err(|error| RuntimeReloadError::Task(error.to_string()))?
    }

    pub(super) async fn reload_transaction(
        self: &Arc<Self>,
        next_spec: RuntimeSpec,
    ) -> Result<RuntimeReloadReport, RuntimeReloadError> {
        let _operation = self.operation.lock().await;
        self.configuration_update_admission()
            .map_err(RuntimeReloadError::ConfigurationPending)?;
        next_spec
            .validate()
            .map_err(RuntimeReloadError::InvalidSpec)?;
        if next_spec.id != self.id() {
            return Err(RuntimeReloadError::InvalidRuntimeId);
        }
        validate_ports(&next_spec, &self.ports).map_err(RuntimeReloadError::Assembly)?;
        let current_spec = self.spec();
        if self.status().state == RuntimeState::Degraded {
            return self
                .recover_degraded_reload_transaction(next_spec, current_spec)
                .await;
        }
        if self.status().state == RuntimeState::Running
            && current_spec.core.is_some()
            && next_spec.core.is_some()
        {
            self.validate_packet_core_mtu(&next_spec)
                .map_err(RuntimeReloadError::UnsupportedSpec)?;
        }
        if current_spec.core.is_some()
            && next_spec.core.is_some()
            && next_spec.core != current_spec.core
        {
            return Err(RuntimeReloadError::UnsupportedSpec(
                "replacing a running Core listener requires a stop/start transaction".into(),
            ));
        }
        let current_listener = current_spec
            .core
            .as_ref()
            .and_then(|_| self.core_listener_addr());
        let current_plans = MutableCapabilityPlan::from_spec(&current_spec, current_listener)
            .map_err(RuntimeReloadError::InvalidSpec)?;
        if next_spec == current_spec {
            let mut resources = RuntimeDomainReport::default();
            if next_spec.core.is_some() {
                resources.push(RuntimeResourceChange::new(
                    RuntimeResource::Core,
                    RuntimeResourceOutcome::Retained,
                ));
            }
            for plan in &current_plans {
                resources.push(resource_change(plan, RuntimeResourceOutcome::Retained));
            }
            return Ok(RuntimeReloadReport {
                generation: self.status().generation,
                committed: false,
                recovery_required: false,
                resources,
            });
        }

        let (mut grant, original, generation, current_core) = {
            let mut control = self.control.lock().expect("runtime control mutex");
            if control.state != RuntimeState::Running {
                return Err(RuntimeReloadError::InvalidState(control.state));
            }
            control.state = RuntimeState::Reloading;
            (
                control.lease_grant.take(),
                control.checkpoint.take(),
                control.generation,
                control.core,
            )
        };

        let prepared_core = if current_spec.core.is_none() && next_spec.core.is_some() {
            match self.start_spec_core(&next_spec).await {
                Ok(value) => value,
                Err(message) => {
                    let state = if self.status().state == RuntimeState::Degraded {
                        RuntimeState::Degraded
                    } else {
                        RuntimeState::Running
                    };
                    self.restore_reload_control(grant, original, generation, state);
                    return Err(RuntimeReloadError::Core {
                        message,
                        report: RuntimeDomainReport::default(),
                    });
                }
            }
        } else {
            None
        };
        if current_spec.core.is_some() && current_core.is_none() {
            self.restore_reload_control(grant, original, generation, RuntimeState::Running);
            return Err(RuntimeReloadError::Core {
                message: "running Runtime spec has no owned Core generation".into(),
                report: RuntimeDomainReport::default(),
            });
        }
        let next_listener = if next_spec.core.is_some() {
            prepared_core.map(|core| core.listener).or(current_listener)
        } else {
            None
        };
        let next_plans = match MutableCapabilityPlan::from_spec(&next_spec, next_listener) {
            Ok(value) => value,
            Err(error) => {
                let mut report = RuntimeDomainReport::default();
                let cleanup_ok = self
                    .rollback_prepared_core(prepared_core, &mut report)
                    .await;
                self.restore_reload_control(
                    grant,
                    original,
                    generation,
                    if cleanup_ok {
                        RuntimeState::Running
                    } else {
                        RuntimeState::Degraded
                    },
                );
                return Err(RuntimeReloadError::Core {
                    message: error.to_string(),
                    report,
                });
            }
        };
        // An open capture takes new exclusions in place, keeping its previous
        // settings for the undo; any other change to it needs a stop/start.
        let capture_update = match (
            &current_spec.platform.packet_capture,
            &next_spec.platform.packet_capture,
        ) {
            (Some(current), Some(next)) if current.differs_only_in_exclusions(next) => {
                Some(current.clone())
            }
            _ => None,
        };
        if capture_update.is_none()
            && current_spec.platform.packet_capture.is_some()
            && next_spec.platform.packet_capture.is_some()
            && current_spec.platform.packet_capture != next_spec.platform.packet_capture
        {
            let mut report = RuntimeDomainReport::default();
            let cleanup_ok = self
                .rollback_prepared_core(prepared_core, &mut report)
                .await;
            self.restore_reload_control(
                grant,
                original,
                generation,
                if cleanup_ok {
                    RuntimeState::Running
                } else {
                    RuntimeState::Degraded
                },
            );
            return Err(RuntimeReloadError::UnsupportedSpec(
                "packet capture settings require a stop/start transaction".into(),
            ));
        }
        let changed = next_plans
            .iter()
            .filter(|next| {
                current_plans
                    .iter()
                    .find(|current| current.lease_key() == next.lease_key())
                    != Some(*next)
            })
            .cloned()
            .collect::<Vec<_>>();
        let removed = current_plans
            .iter()
            .filter(|current| {
                !next_plans
                    .iter()
                    .any(|next| next.lease_key() == current.lease_key())
            })
            .cloned()
            .collect::<Vec<_>>();
        let retained = next_plans
            .iter()
            .filter(|next| {
                current_plans
                    .iter()
                    .find(|current| current.lease_key() == next.lease_key())
                    == Some(*next)
            })
            .cloned()
            .collect::<Vec<_>>();
        let current_lease_keys = lease_keys(&current_spec);
        let target_lease_keys = lease_keys(&next_spec);
        let union_keys = union_lease_keys(&current_lease_keys, &target_lease_keys);
        let mut lease_mutation = ReloadLeaseMutation::None;
        if grant.is_none() && !union_keys.is_empty() {
            let request = LeaseRequestSet::new(self.id(), union_keys.clone())
                .expect("non-empty reload lease request");
            match self.lease_coordinator.acquire_all(request) {
                Ok(value) => {
                    grant = Some(value);
                    lease_mutation = ReloadLeaseMutation::Acquired;
                }
                Err(error) => {
                    let mut report = RuntimeDomainReport::default();
                    let cleanup_ok = self
                        .rollback_prepared_core(prepared_core, &mut report)
                        .await;
                    self.restore_reload_control(
                        None,
                        original,
                        generation,
                        if cleanup_ok {
                            RuntimeState::Running
                        } else {
                            RuntimeState::Degraded
                        },
                    );
                    return Err(RuntimeReloadError::LeaseConflict { error, report });
                }
            }
        } else if let Some(current_grant) = grant.take() {
            if union_keys != current_grant.keys() {
                if current_grant
                    .keys()
                    .iter()
                    .any(|key| !union_keys.contains(key))
                    || union_keys.len() <= current_grant.keys().len()
                {
                    let error = LeaseTransitionError {
                        code: crate::LeaseTransitionErrorCode::GrantMismatch,
                        message: "running lease grant does not match the committed Runtime spec"
                            .into(),
                    };
                    grant = Some(current_grant);
                    let mut report = RuntimeDomainReport::default();
                    let cleanup_ok = self
                        .rollback_prepared_core(prepared_core, &mut report)
                        .await;
                    self.restore_reload_control(
                        grant,
                        original,
                        generation,
                        if cleanup_ok {
                            RuntimeState::Running
                        } else {
                            RuntimeState::Degraded
                        },
                    );
                    return Err(RuntimeReloadError::LeaseTransition { error, report });
                }
                let previous_keys = current_grant.keys().to_vec();
                let request = LeaseRequestSet::new(self.id(), union_keys.clone())
                    .expect("non-empty expanded reload lease request");
                match self.lease_coordinator.expand(&current_grant, request) {
                    Ok(value) => {
                        grant = Some(value);
                        lease_mutation = ReloadLeaseMutation::Expanded { previous_keys };
                    }
                    Err(error) => {
                        grant = Some(current_grant);
                        let mut report = RuntimeDomainReport::default();
                        let cleanup_ok = self
                            .rollback_prepared_core(prepared_core, &mut report)
                            .await;
                        self.restore_reload_control(
                            grant,
                            original,
                            generation,
                            if cleanup_ok {
                                RuntimeState::Running
                            } else {
                                RuntimeState::Degraded
                            },
                        );
                        return Err(match error {
                            LeaseExpandError::Conflict(error) => {
                                RuntimeReloadError::LeaseConflict { error, report }
                            }
                            LeaseExpandError::Transition(error) => {
                                RuntimeReloadError::LeaseTransition { error, report }
                            }
                        });
                    }
                }
            } else {
                grant = Some(current_grant);
            }
        }

        let mut prepared = Vec::with_capacity(changed.len());
        for plan in &changed {
            let checkpoint = match (plan, &capture_update) {
                // The capture's own checkpoint already restores the session
                // its exclusions live in.
                (MutableCapabilityPlan::PacketCapture(settings), Some(_)) => self
                    .validate_excluded_prefixes(
                        CapabilityKind::PacketCapture,
                        &settings.excluded_prefixes,
                    )
                    .map(|()| None),
                _ => plan.prepare(self).await.map(Some),
            };
            match checkpoint {
                Ok(Some(value)) => prepared.push((plan.lease_key(), value)),
                Ok(None) => {}
                Err(error) => {
                    let report = self
                        .rollback_uncommitted_reload(
                            grant,
                            lease_mutation,
                            original,
                            generation,
                            prepared_core,
                            LeaseReleaseEvidence::NoModification,
                            RuntimeDomainReport::default(),
                        )
                        .await?;
                    return Err(RuntimeReloadError::Capability { error, report });
                }
            }
        }

        let has_platform_changes = !changed.is_empty() || !removed.is_empty();
        let mut transaction = if has_platform_changes {
            let mut capabilities = original
                .as_ref()
                .map(|stored| stored.checkpoint.capabilities.clone())
                .unwrap_or_default();
            for (key, baseline) in &prepared {
                if let Some(capability) = capabilities
                    .iter_mut()
                    .find(|capability| capability.lease_key == *key)
                {
                    capability.rollback_payload = Some(baseline.payload.clone());
                } else {
                    capabilities.push(baseline.clone());
                }
            }
            capabilities.sort_by_key(|capability| capability_rank(&capability.lease_key));
            let checkpoint = RecoveryCheckpoint::new(
                original
                    .as_ref()
                    .map(|stored| stored.checkpoint.id)
                    .unwrap_or_else(CheckpointId::new),
                self.id(),
                generation.next(),
                CheckpointOperation::Reload,
                CheckpointPhase::Prepared,
                capabilities,
            )
            .and_then(|checkpoint| checkpoint.with_leases(union_keys.clone()));
            let checkpoint = match checkpoint {
                Ok(checkpoint) => checkpoint,
                Err(error) => {
                    let capability = changed
                        .first()
                        .or_else(|| removed.first())
                        .map(MutableCapabilityPlan::capability)
                        .unwrap_or(CapabilityKind::Unknown);
                    let report = self
                        .rollback_uncommitted_reload(
                            grant,
                            lease_mutation,
                            original,
                            generation,
                            prepared_core,
                            LeaseReleaseEvidence::NoModification,
                            RuntimeDomainReport::default(),
                        )
                        .await?;
                    return Err(RuntimeReloadError::Capability {
                        error: checkpoint_contract_error(
                            capability,
                            "invalid prepared reload checkpoint",
                            error,
                        ),
                        report,
                    });
                }
            };
            let stored = match original.as_ref() {
                Some(original) => {
                    self.checkpoint_store
                        .replace(original.revision, checkpoint)
                        .await
                }
                None => self.checkpoint_store.create(checkpoint).await,
            };
            match stored {
                Ok(value) => Some(value),
                Err(error) => {
                    let report = self
                        .rollback_uncommitted_reload(
                            grant,
                            lease_mutation,
                            original,
                            generation,
                            prepared_core,
                            LeaseReleaseEvidence::NoModification,
                            RuntimeDomainReport::default(),
                        )
                        .await?;
                    return Err(RuntimeReloadError::Store { error, report });
                }
            }
        } else {
            original.clone()
        };
        if let Some(stored) = transaction.as_mut() {
            stored.checkpoint.phase = CheckpointPhase::Applying;
            *stored = match self
                .checkpoint_store
                .replace(stored.revision, stored.checkpoint.clone())
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    self.retain_recovery(grant, stored.clone());
                    return Err(RuntimeReloadError::Store {
                        error,
                        report: RuntimeDomainReport::default(),
                    });
                }
            };
        }

        let mut report = RuntimeDomainReport::default();
        for plan in &retained {
            report.push(resource_change(plan, RuntimeResourceOutcome::Retained));
        }
        let mut undos = Vec::new();
        let mut operation_error = None;
        let mut restore_failed = false;
        for plan in &changed {
            let applied = match (plan, &capture_update) {
                (MutableCapabilityPlan::PacketCapture(settings), Some(previous)) => {
                    undos.push(CapabilityUndo::UpdateCapture(previous.clone()));
                    self.update_packet_capture(settings).await
                }
                _ => {
                    let baseline = prepared
                        .iter()
                        .find(|(key, _)| *key == plan.lease_key())
                        .expect("prepared changed capability")
                        .1
                        .clone();
                    undos.push(CapabilityUndo::Restore(baseline));
                    plan.apply(self).await
                }
            };
            match applied {
                Ok(applied) if applied.verified => {
                    report.push(resource_change(plan, RuntimeResourceOutcome::Applied));
                }
                Ok(_) => {
                    operation_error = Some(CapabilityError::new(
                        plan.capability(),
                        crate::CapabilityErrorCode::ApplyFailed,
                        "capability apply was not verified",
                    ));
                    break;
                }
                Err(error) => {
                    operation_error = Some(error);
                    break;
                }
            }
        }
        if operation_error.is_none() {
            for plan in removed.iter().rev() {
                let checkpoint = transaction
                    .as_ref()
                    .expect("removed capability reload checkpoint")
                    .checkpoint
                    .capabilities
                    .iter()
                    .find(|capability| capability.lease_key == plan.lease_key())
                    .expect("removed capability checkpoint")
                    .clone();
                undos.push(CapabilityUndo::Apply(plan.clone()));
                match self.restore_capability(&checkpoint).await {
                    Ok(restored) if restored.verified => {
                        report.push(resource_change(plan, RuntimeResourceOutcome::Restored));
                    }
                    Ok(_) => {
                        restore_failed = true;
                        operation_error = Some(CapabilityError::new(
                            plan.capability(),
                            crate::CapabilityErrorCode::RestoreFailed,
                            "capability restore was not verified",
                        ));
                        break;
                    }
                    Err(error) => {
                        restore_failed = true;
                        operation_error = Some(error);
                        break;
                    }
                }
            }
        }
        if let Some(error) = operation_error {
            let rollback_verified = !restore_failed && self.rollback_capability_undos(&undos).await;
            for undo in &undos {
                report.push(RuntimeResourceChange::new(
                    undo.resource(),
                    if rollback_verified {
                        RuntimeResourceOutcome::RolledBack
                    } else {
                        RuntimeResourceOutcome::RecoveryRequired
                    },
                ));
            }
            if rollback_verified {
                let restored = match self
                    .restore_original_checkpoint(original.as_ref(), transaction.as_ref())
                    .await
                {
                    Ok(value) => value,
                    Err(store_error) => {
                        if let Some(transaction) = transaction {
                            self.retain_recovery(grant, transaction);
                        }
                        return Err(RuntimeReloadError::Store {
                            error: store_error,
                            report,
                        });
                    }
                };
                let report = self
                    .rollback_uncommitted_reload(
                        grant,
                        lease_mutation,
                        restored,
                        generation,
                        prepared_core,
                        LeaseReleaseEvidence::VerifiedRestore,
                        report,
                    )
                    .await?;
                return Err(RuntimeReloadError::Capability { error, report });
            }
            let mut transaction = transaction.expect("platform reload transaction");
            transaction.checkpoint.phase = CheckpointPhase::RecoveryRequired;
            transaction.checkpoint.leases = union_keys;
            let transaction = self
                .checkpoint_store
                .replace(transaction.revision, transaction.checkpoint.clone())
                .await
                .unwrap_or(transaction);
            self.retain_recovery(grant, transaction);
            return Err(RuntimeReloadError::RecoveryRequired { error, report });
        }

        let mut target_stored = if has_platform_changes && !next_plans.is_empty() {
            let mut transaction = transaction.take().expect("platform reload transaction");
            let transaction_capabilities = transaction.checkpoint.capabilities.clone();
            transaction.checkpoint.capabilities = next_plans
                .iter()
                .map(|plan| {
                    transaction_capabilities
                        .iter()
                        .find(|capability| capability.lease_key == plan.lease_key())
                        .cloned()
                        .expect("target capability checkpoint")
                })
                .collect();
            transaction.checkpoint.leases = target_lease_keys.clone();
            transaction.checkpoint.phase = CheckpointPhase::Applying;
            transaction = match self
                .checkpoint_store
                .replace(transaction.revision, transaction.checkpoint.clone())
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    self.retain_recovery(grant, transaction);
                    return Err(RuntimeReloadError::Store { error, report });
                }
            };
            Some(transaction)
        } else if has_platform_changes {
            None
        } else {
            transaction.take()
        };

        if has_platform_changes && next_plans.is_empty() {
            let transaction = transaction
                .take()
                .expect("full platform restore checkpoint");
            if let Some(value) = grant.take() {
                if let Err(error) = self.lease_coordinator.begin_release(&value) {
                    self.retain_recovery(Some(value), transaction);
                    return Err(RuntimeReloadError::LeaseTransition { error, report });
                }
                if let Err(error) = self
                    .checkpoint_store
                    .delete(transaction.checkpoint.id, transaction.revision)
                    .await
                {
                    self.retain_recovery(Some(value), transaction);
                    return Err(RuntimeReloadError::Store { error, report });
                }
                if let Err(mut error) = self
                    .lease_coordinator
                    .release(&value, LeaseReleaseEvidence::VerifiedRestore)
                {
                    let (transaction, store_error) =
                        self.recreate_deleted_checkpoint(transaction).await;
                    if let Some(store_error) = store_error {
                        error.message = format!(
                            "{}; failed to recreate recovery checkpoint: {store_error}",
                            error.message
                        );
                    }
                    self.retain_recovery(Some(value), transaction);
                    return Err(RuntimeReloadError::LeaseTransition { error, report });
                }
            } else if let Err(error) = self
                .checkpoint_store
                .delete(transaction.checkpoint.id, transaction.revision)
                .await
            {
                self.retain_recovery(None, transaction);
                return Err(RuntimeReloadError::Store { error, report });
            }
        } else if let Some(value) = grant.take() {
            if target_lease_keys.len() < value.keys().len() {
                match self.lease_coordinator.shrink(
                    &value,
                    target_lease_keys.clone(),
                    LeaseReleaseEvidence::VerifiedRestore,
                ) {
                    Ok(replacement) => grant = Some(replacement),
                    Err(error) => {
                        let mut target = target_stored.expect("target reload checkpoint");
                        target.checkpoint.phase = CheckpointPhase::RecoveryRequired;
                        target.checkpoint.leases = union_keys;
                        let target = self
                            .checkpoint_store
                            .replace(target.revision, target.checkpoint.clone())
                            .await
                            .unwrap_or(target);
                        self.retain_recovery(Some(value), target);
                        return Err(RuntimeReloadError::LeaseTransition { error, report });
                    }
                }
            } else {
                grant = Some(value);
            }
        }

        if let Some(stored) = target_stored.as_mut() {
            stored.checkpoint.phase = CheckpointPhase::Committed;
            *stored = match self
                .checkpoint_store
                .replace(stored.revision, stored.checkpoint.clone())
                .await
            {
                Ok(value) => value,
                Err(error) => {
                    self.retain_recovery(grant, stored.clone());
                    return Err(RuntimeReloadError::Store { error, report });
                }
            };
        }

        if current_spec.core.is_some() && next_spec.core.is_none() {
            if let Some(active) = current_core {
                match self.core.stop_generation(active).await {
                    Ok(Some(_)) => {
                        let mut control = self.control.lock().expect("runtime control mutex");
                        if control.core == Some(active) {
                            control.core = None;
                        }
                        report.push(RuntimeResourceChange::new(
                            RuntimeResource::Core,
                            RuntimeResourceOutcome::Restored,
                        ));
                    }
                    Ok(None) | Err(_) => {
                        let message = "failed to stop the Runtime's Core generation";
                        report.push(
                            RuntimeResourceChange::new(
                                RuntimeResource::Core,
                                RuntimeResourceOutcome::RecoveryRequired,
                            )
                            .with_message(message),
                        );
                        let mut control = self.control.lock().expect("runtime control mutex");
                        control.generation = generation;
                        control.state = RuntimeState::Degraded;
                        control.lease_grant = grant;
                        control.checkpoint = target_stored;
                        control.degradation_error = Some(message.into());
                        return Err(RuntimeReloadError::Core {
                            message: message.into(),
                            report,
                        });
                    }
                }
            }
        } else if current_spec.core.is_none() && next_spec.core.is_some() {
            report.push(RuntimeResourceChange::new(
                RuntimeResource::Core,
                RuntimeResourceOutcome::Applied,
            ));
        } else if next_spec.core.is_some() {
            report.push(RuntimeResourceChange::new(
                RuntimeResource::Core,
                RuntimeResourceOutcome::Retained,
            ));
        }

        let mut control = self.control.lock().expect("runtime control mutex");
        control.spec = next_spec;
        control.generation = generation.next();
        control.state = RuntimeState::Running;
        control.lease_grant = grant;
        control.checkpoint = target_stored;
        control.degradation_error = None;
        Ok(RuntimeReloadReport {
            generation: control.generation,
            committed: true,
            recovery_required: false,
            resources: report,
        })
    }

    /// Recovers a degraded Runtime toward `next_spec` while keeping its Core:
    /// every resource `next_spec` drops is restored, and the rest is kept
    /// exactly as committed. Keeping a mutable resource is allowed only after
    /// a platform session loss, and only for resources that did not live in
    /// that session (the system proxy): nothing touched it, so it is still as
    /// committed. Any other degradation vouches for
    /// nothing, so it must shrink to the Core. The recovery never adds or
    /// changes a resource; a host grows again with an ordinary reload.
    pub(super) async fn recover_degraded_reload_transaction(
        &self,
        next_spec: RuntimeSpec,
        current_spec: RuntimeSpec,
    ) -> Result<RuntimeReloadReport, RuntimeReloadError> {
        if next_spec.core != current_spec.core {
            return Err(RuntimeReloadError::UnsupportedSpec(
                "degraded reload recovery keeps the existing Core".into(),
            ));
        }
        let listener = current_spec
            .core
            .as_ref()
            .and_then(|_| self.core_listener_addr());
        let current_plans = MutableCapabilityPlan::from_spec(&current_spec, listener)
            .map_err(RuntimeReloadError::InvalidSpec)?;
        let retained_plans = MutableCapabilityPlan::from_spec(&next_spec, listener)
            .map_err(RuntimeReloadError::InvalidSpec)?;
        if retained_plans
            .iter()
            .any(|plan| !current_plans.contains(plan))
        {
            return Err(RuntimeReloadError::UnsupportedSpec(
                "degraded reload recovery only drops resources; it cannot add or change them"
                    .into(),
            ));
        }
        let mut retained_keys = retained_plans
            .iter()
            .map(MutableCapabilityPlan::lease_key)
            .collect::<Vec<_>>();
        retained_keys.sort();
        retained_keys.dedup();

        let (mut grant, mut stored, generation, current_core) = {
            let mut control = self.control.lock().expect("runtime control mutex");
            if control.state != RuntimeState::Degraded {
                return Err(RuntimeReloadError::InvalidState(control.state));
            }
            let session_lost = control.session_lost;
            if !retained_plans.is_empty()
                && !(session_lost
                    && retained_plans
                        .iter()
                        .all(|plan| !plan.lives_in_platform_session()))
            {
                return Err(RuntimeReloadError::UnsupportedSpec(
                    "degraded reload recovery keeps only resources outside a lost platform session"
                        .into(),
                ));
            }
            let Some(stored) = control.checkpoint.take() else {
                return Err(RuntimeReloadError::Cleanup {
                    message: "degraded reload recovery has no checkpoint".into(),
                    report: RuntimeDomainReport::default(),
                });
            };
            let recoverable = stored.checkpoint.phase == CheckpointPhase::RecoveryRequired
                && (session_lost || stored.checkpoint.operation == CheckpointOperation::Reload);
            if !recoverable {
                control.checkpoint = Some(stored);
                return Err(RuntimeReloadError::UnsupportedSpec(
                    "degraded Runtime is neither retrying a recovery-required reload nor recovering a lost platform session"
                        .into(),
                ));
            }
            if next_spec.core.is_some() && control.core.is_none() {
                control.checkpoint = Some(stored);
                return Err(RuntimeReloadError::Core {
                    message: "degraded reload recovery has no retained Core generation".into(),
                    report: RuntimeDomainReport::default(),
                });
            }
            control.state = RuntimeState::Reloading;
            (
                control.lease_grant.take(),
                stored,
                control.generation,
                control.core,
            )
        };

        let mut report = RuntimeDomainReport::default();
        if let Some(value) = grant.as_ref() {
            if let Err(error) = self.lease_coordinator.begin_recovery(value) {
                self.retain_recovery(grant, stored);
                return Err(RuntimeReloadError::LeaseTransition { error, report });
            }
        }

        stored.checkpoint.phase = CheckpointPhase::Restoring;
        stored = match self.persist_checkpoint(&stored).await {
            Ok(value) => value,
            Err(error) => {
                self.retain_recovery(grant, stored);
                return Err(RuntimeReloadError::Store { error, report });
            }
        };

        for capability in stored.checkpoint.capabilities.clone().iter().rev() {
            if retained_keys.contains(&capability.lease_key) {
                continue;
            }
            let resource = resource_for_key(&capability.lease_key);
            match self.restore_capability(capability).await {
                Ok(restored) if restored.verified => report.push(RuntimeResourceChange::new(
                    resource,
                    RuntimeResourceOutcome::Restored,
                )),
                Ok(_) => {
                    report.push(
                        RuntimeResourceChange::new(
                            resource,
                            RuntimeResourceOutcome::RecoveryRequired,
                        )
                        .with_message("capability recovery was not verified"),
                    );
                    stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
                    if let Ok(value) = self.persist_checkpoint(&stored).await {
                        stored = value;
                    }
                    self.retain_recovery(grant, stored);
                    return Err(RuntimeReloadError::Cleanup {
                        message: "capability recovery was not verified".into(),
                        report,
                    });
                }
                Err(error) => {
                    report.push(
                        RuntimeResourceChange::new(
                            resource,
                            RuntimeResourceOutcome::RecoveryRequired,
                        )
                        .with_message(error.to_string()),
                    );
                    stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
                    if let Ok(value) = self.persist_checkpoint(&stored).await {
                        stored = value;
                    }
                    self.retain_recovery(grant, stored);
                    return Err(RuntimeReloadError::Capability { error, report });
                }
            }
        }

        let (generation, checkpoint) = if retained_keys.is_empty() {
            let generation = stored.checkpoint.generation;
            if let Some(value) = grant.take() {
                if let Err(error) = self.delete_checkpoint_if_present(&stored).await {
                    self.retain_recovery(Some(value), stored);
                    return Err(RuntimeReloadError::Store { error, report });
                }
                if let Err(mut error) = self
                    .lease_coordinator
                    .release(&value, LeaseReleaseEvidence::VerifiedRestore)
                {
                    let (replacement, store_error) = self.recreate_deleted_checkpoint(stored).await;
                    stored = replacement;
                    if let Some(store_error) = store_error {
                        error.message = format!(
                            "{}; failed to recreate recovery checkpoint: {store_error}",
                            error.message
                        );
                    }
                    self.retain_recovery(Some(value), stored);
                    return Err(RuntimeReloadError::LeaseTransition { error, report });
                }
            } else if let Err(error) = self.delete_checkpoint_if_present(&stored).await {
                self.retain_recovery(None, stored);
                return Err(RuntimeReloadError::Store { error, report });
            }
            (generation, None)
        } else {
            if let Some(value) = grant.take() {
                if let Err(error) = self.lease_coordinator.resume(&value) {
                    self.retain_recovery(Some(value), stored);
                    return Err(RuntimeReloadError::LeaseTransition { error, report });
                }
                if retained_keys.len() < value.keys().len() {
                    match self.lease_coordinator.shrink(
                        &value,
                        retained_keys.clone(),
                        LeaseReleaseEvidence::VerifiedRestore,
                    ) {
                        Ok(replacement) => grant = Some(replacement),
                        Err(error) => {
                            stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
                            if let Ok(value) = self.persist_checkpoint(&stored).await {
                                stored = value;
                            }
                            self.retain_recovery(Some(value), stored);
                            return Err(RuntimeReloadError::LeaseTransition { error, report });
                        }
                    }
                } else {
                    grant = Some(value);
                }
            }
            let generation = generation.next();
            stored
                .checkpoint
                .capabilities
                .retain(|capability| retained_keys.contains(&capability.lease_key));
            stored.checkpoint.leases = retained_keys.clone();
            stored.checkpoint.generation = generation;
            stored.checkpoint.operation = CheckpointOperation::Reload;
            stored.checkpoint.phase = CheckpointPhase::Committed;
            stored = match self.persist_checkpoint(&stored).await {
                Ok(value) => value,
                Err(error) => {
                    self.retain_recovery(grant, stored);
                    return Err(RuntimeReloadError::Store { error, report });
                }
            };
            for plan in &retained_plans {
                report.push(resource_change(plan, RuntimeResourceOutcome::Retained));
            }
            (generation, Some(stored))
        };

        if current_core.is_some() {
            report.push(RuntimeResourceChange::new(
                RuntimeResource::Core,
                RuntimeResourceOutcome::Retained,
            ));
        }
        let mut control = self.control.lock().expect("runtime control mutex");
        control.spec = next_spec;
        control.generation = generation;
        control.state = RuntimeState::Running;
        control.lease_grant = grant;
        control.checkpoint = checkpoint;
        control.degradation_error = None;
        control.session_lost = false;
        Ok(RuntimeReloadReport {
            generation,
            committed: true,
            recovery_required: false,
            resources: report,
        })
    }

    pub(super) fn restore_reload_control(
        &self,
        grant: Option<LeaseGrant>,
        checkpoint: Option<StoredCheckpoint>,
        generation: RuntimeGeneration,
        state: RuntimeState,
    ) {
        let mut control = self.control.lock().expect("runtime control mutex");
        control.generation = generation;
        control.state = state;
        control.lease_grant = grant;
        control.checkpoint = checkpoint;
    }

    pub(super) fn degrade_reload_control(
        &self,
        grant: Option<LeaseGrant>,
        checkpoint: Option<StoredCheckpoint>,
        generation: RuntimeGeneration,
        message: String,
    ) {
        let mut control = self.control.lock().expect("runtime control mutex");
        control.generation = generation;
        control.state = RuntimeState::Degraded;
        control.lease_grant = grant;
        control.checkpoint = checkpoint;
        control.degradation_error = Some(message);
    }

    pub(super) async fn rollback_uncommitted_reload(
        &self,
        grant: Option<LeaseGrant>,
        lease_mutation: ReloadLeaseMutation,
        checkpoint: Option<StoredCheckpoint>,
        generation: RuntimeGeneration,
        prepared_core: Option<PreparedRuntimeCore>,
        evidence: LeaseReleaseEvidence,
        mut report: RuntimeDomainReport,
    ) -> Result<RuntimeDomainReport, RuntimeReloadError> {
        if !self
            .rollback_prepared_core(prepared_core, &mut report)
            .await
        {
            let message = "failed reload could not stop the Core it started".to_string();
            self.degrade_reload_control(grant, checkpoint, generation, message.clone());
            return Err(RuntimeReloadError::Cleanup { message, report });
        }

        match self.rollback_reload_grant(grant, lease_mutation, evidence) {
            Ok(grant) => {
                self.restore_reload_control(grant, checkpoint, generation, RuntimeState::Running);
                Ok(report)
            }
            Err((error, retained_grant)) => {
                self.degrade_reload_control(
                    retained_grant,
                    checkpoint,
                    generation,
                    error.to_string(),
                );
                Err(RuntimeReloadError::LeaseTransition { error, report })
            }
        }
    }

    pub(super) fn rollback_reload_grant(
        &self,
        grant: Option<LeaseGrant>,
        mutation: ReloadLeaseMutation,
        evidence: LeaseReleaseEvidence,
    ) -> Result<Option<LeaseGrant>, (LeaseTransitionError, Option<LeaseGrant>)> {
        match (grant, mutation) {
            (grant, ReloadLeaseMutation::None) => Ok(grant),
            (Some(grant), ReloadLeaseMutation::Acquired) => {
                let transition = if evidence == LeaseReleaseEvidence::NoModification {
                    Ok(())
                } else {
                    self.lease_coordinator.begin_release(&grant)
                };
                if let Err(error) = transition {
                    return Err((error, Some(grant)));
                }
                match self.lease_coordinator.release(&grant, evidence) {
                    Ok(()) => Ok(None),
                    Err(error) => Err((error, Some(grant))),
                }
            }
            (Some(grant), ReloadLeaseMutation::Expanded { previous_keys }) => {
                match self
                    .lease_coordinator
                    .shrink(&grant, previous_keys, evidence)
                {
                    Ok(replacement) => Ok(Some(replacement)),
                    Err(error) => Err((error, Some(grant))),
                }
            }
            (None, _) => Ok(None),
        }
    }

    pub(super) async fn rollback_capability_undos(
        self: &Arc<Self>,
        undos: &[CapabilityUndo],
    ) -> bool {
        let mut verified = true;
        for undo in undos.iter().rev() {
            let result = match undo {
                CapabilityUndo::Restore(checkpoint) => self.restore_capability(checkpoint).await,
                CapabilityUndo::Apply(plan) => plan.apply(self).await,
                CapabilityUndo::UpdateCapture(settings) => {
                    self.update_packet_capture(settings).await
                }
            };
            verified &= result.is_ok_and(|report| report.verified);
        }
        verified
    }
}
