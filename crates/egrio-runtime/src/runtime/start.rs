//! The start transaction: checkpoint first, then apply each capability in
//! order, committing only after every one is observed.
use super::*;

impl Runtime {
    pub async fn start(self: &Arc<Self>) -> Result<RuntimeStartReport, RuntimeStartError> {
        let runtime = self.clone();
        self.spawn(async move {
            let report = runtime.start_transaction(None).await?;
            // Attach the disconnect watcher inside the spawned task, not in the
            // caller's future: the transaction runs detached precisely so a
            // dropped caller future cannot corrupt it, and a runtime committed
            // Running without a watcher would silently never degrade on a later
            // disconnect. Running it here keeps commit-and-watch atomic.
            runtime.sync_health_watcher().await;
            Ok(report)
        })
        .await
        .map_err(|error| RuntimeStartError::Task(error.to_string()))?
    }

    /// Starts a Created or Stopped Runtime directly with a replacement spec.
    /// Running topology changes must use `reload`.
    pub async fn start_with_spec(
        self: &Arc<Self>,
        spec: RuntimeSpec,
    ) -> Result<RuntimeStartReport, RuntimeStartError> {
        let runtime = self.clone();
        self.spawn(async move {
            let report = runtime.start_transaction(Some(spec)).await?;
            runtime.sync_health_watcher().await;
            Ok(report)
        })
        .await
        .map_err(|error| RuntimeStartError::Task(error.to_string()))?
    }

    pub(super) async fn rollback_uncheckpointed_start(
        &self,
        grant: Option<LeaseGrant>,
        started_core: Option<PreparedRuntimeCore>,
    ) -> Result<(), RuntimeStartError> {
        if !self.abandon_start_core(started_core).await {
            let message = "failed start could not stop the Core it started".to_string();
            self.degrade_without_checkpoint(grant, message.clone());
            return Err(RuntimeStartError::Cleanup(message));
        }

        if let Some(grant) = grant {
            if let Err(error) = self
                .lease_coordinator
                .release(&grant, LeaseReleaseEvidence::NoModification)
            {
                let message = format!("failed start could not release its lease grant: {error}");
                self.degrade_without_checkpoint(Some(grant), message.clone());
                return Err(RuntimeStartError::Cleanup(message));
            }
        }

        let mut control = self.control.lock().expect("runtime control mutex");
        control.state = RuntimeState::Created;
        control.lease_grant = None;
        control.checkpoint = None;
        control.degradation_error = None;
        Ok(())
    }

    pub(super) fn degrade_without_checkpoint(&self, grant: Option<LeaseGrant>, message: String) {
        let mut control = self.control.lock().expect("runtime control mutex");
        control.state = RuntimeState::Degraded;
        control.lease_grant = grant;
        control.checkpoint = None;
        control.degradation_error = Some(message);
    }

    pub(super) async fn start_transaction(
        self: &Arc<Self>,
        requested_spec: Option<RuntimeSpec>,
    ) -> Result<RuntimeStartReport, RuntimeStartError> {
        let _operation = self.operation.lock().await;
        self.clear_session_loss();
        if let Some(spec) = requested_spec.as_ref() {
            spec.validate()
                .map_err(|error| RuntimeStartError::UnsupportedSpec(error.to_string()))?;
            if spec.id != self.id() {
                return Err(RuntimeStartError::UnsupportedSpec(
                    "start cannot change runtime id".into(),
                ));
            }
            validate_ports(spec, &self.ports)
                .map_err(|error| RuntimeStartError::UnsupportedSpec(error.to_string()))?;
        }
        {
            let mut control = self.control.lock().expect("runtime control mutex");
            if control.state == RuntimeState::Running {
                if requested_spec
                    .as_ref()
                    .is_some_and(|spec| spec != &control.spec)
                {
                    return Err(RuntimeStartError::UnsupportedSpec(
                        "running Runtime topology changes must use reload".into(),
                    ));
                }
                let listener = control
                    .spec
                    .core
                    .as_ref()
                    .and_then(|_| self.core_listener_addr());
                let plans =
                    MutableCapabilityPlan::from_spec(&control.spec, listener).unwrap_or_default();
                let mut resources = RuntimeDomainReport::default();
                if control.spec.core.is_some() {
                    resources.push(RuntimeResourceChange::new(
                        RuntimeResource::Core,
                        RuntimeResourceOutcome::Retained,
                    ));
                }
                for plan in &plans {
                    resources.push(resource_change(plan, RuntimeResourceOutcome::Retained));
                }
                return Ok(RuntimeStartReport {
                    generation: control.generation,
                    changed: false,
                    checkpoint_id: control.checkpoint.as_ref().map(|value| value.checkpoint.id),
                    resources,
                });
            }
            if control.state != RuntimeState::Created && control.state != RuntimeState::Stopped {
                return Err(RuntimeStartError::InvalidState(control.state));
            }
            if let Some(spec) = requested_spec {
                control.spec = spec;
            }
            control.state = RuntimeState::Starting;
        }
        let spec = self.spec();

        // The spec-declared Core and its listener come first: a listener bind
        // failure must surface before any lease is acquired, any checkpoint
        // is written, or any OS adapter runs.
        let started_core = match self.start_spec_core(&spec).await {
            Ok(value) => value,
            Err(message) => {
                if self.status().state != RuntimeState::Degraded {
                    self.set_state(RuntimeState::Created);
                }
                return Err(RuntimeStartError::Core(message));
            }
        };
        let core_listener = started_core.map(|core| core.listener);
        let plans = match MutableCapabilityPlan::from_spec(&spec, core_listener) {
            Ok(value) => value,
            Err(error) => {
                if self.abandon_start_core(started_core).await {
                    self.set_state(RuntimeState::Created);
                }
                return Err(RuntimeStartError::Core(error.to_string()));
            }
        };

        let lease_request = spec
            .lease_request()
            .expect("validated start spec lease request");
        let mut grant = match lease_request.clone() {
            Some(request) => match self.lease_coordinator.acquire_all(request) {
                Ok(value) => Some(value),
                Err(error) => {
                    if self.abandon_start_core(started_core).await {
                        self.set_state(RuntimeState::Created);
                    }
                    return Err(RuntimeStartError::LeaseConflict(error));
                }
            },
            None => None,
        };

        if plans.is_empty() {
            let mut resources = RuntimeDomainReport::default();
            if started_core.is_some() {
                resources.push(RuntimeResourceChange::new(
                    RuntimeResource::Core,
                    RuntimeResourceOutcome::Applied,
                ));
            }
            let mut control = self.control.lock().expect("runtime control mutex");
            control.generation = control.generation.next();
            control.state = RuntimeState::Running;
            control.lease_grant = grant;
            return Ok(RuntimeStartReport {
                generation: control.generation,
                changed: true,
                checkpoint_id: None,
                resources,
            });
        }
        let mut capabilities = Vec::with_capacity(plans.len());
        for plan in &plans {
            match plan.prepare(self).await {
                Ok(value) => capabilities.push(value),
                Err(error) => {
                    self.rollback_uncheckpointed_start(grant.take(), started_core)
                        .await?;
                    return Err(RuntimeStartError::Capability(error));
                }
            }
        }
        let checkpoint = RecoveryCheckpoint::new(
            CheckpointId::new(),
            self.id(),
            RuntimeGeneration::new(self.status().generation.get() + 1),
            CheckpointOperation::Start,
            CheckpointPhase::Prepared,
            capabilities.clone(),
        )
        .and_then(|checkpoint| {
            let mut leases = checkpoint.leases.clone();
            if let Some(request) = lease_request.as_ref() {
                leases.extend_from_slice(request.keys());
            }
            checkpoint.with_leases(leases)
        });
        let checkpoint = match checkpoint {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                self.rollback_uncheckpointed_start(grant.take(), started_core)
                    .await?;
                let capability = plans
                    .first()
                    .map(MutableCapabilityPlan::capability)
                    .unwrap_or(CapabilityKind::Unknown);
                return Err(RuntimeStartError::Capability(checkpoint_contract_error(
                    capability,
                    "invalid prepared start checkpoint",
                    error,
                )));
            }
        };
        let mut stored = match self.checkpoint_store.create(checkpoint).await {
            Ok(value) => value,
            Err(error) => {
                self.rollback_uncheckpointed_start(grant.take(), started_core)
                    .await?;
                return Err(RuntimeStartError::Store(error));
            }
        };
        stored.checkpoint.phase = CheckpointPhase::Applying;
        stored = match self
            .checkpoint_store
            .replace(stored.revision, stored.checkpoint.clone())
            .await
        {
            Ok(value) => value,
            Err(error) => {
                self.retain_recovery(grant, stored);
                return Err(RuntimeStartError::Store(error));
            }
        };

        // The final iteration is the commit gate: persistence may yield while
        // workers run, so check their completion again after that write and
        // compensate through the same undo path as an apply failure.
        for failed_index in 0..=plans.len() {
            let apply_error = if let Some(plan) = plans.get(failed_index) {
                match plan.apply(self).await {
                    Ok(report) if report.verified => self.completed_task_error(),
                    Ok(_) => Some(CapabilityError::new(
                        plan.capability(),
                        crate::CapabilityErrorCode::ApplyFailed,
                        "capability apply was not verified",
                    )),
                    Err(error) => Some(error),
                }
            } else {
                stored.checkpoint.phase = CheckpointPhase::Committed;
                stored = match self
                    .checkpoint_store
                    .replace(stored.revision, stored.checkpoint.clone())
                    .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        self.retain_recovery(grant, stored);
                        return Err(RuntimeStartError::Store(error));
                    }
                };
                self.completed_task_error()
            };
            if let Some(apply_error) = apply_error {
                let mut rollback_verified = true;
                for rollback_plan in plans[..=failed_index.min(plans.len() - 1)].iter().rev() {
                    let checkpoint = capabilities
                        .iter()
                        .find(|value| value.lease_key == rollback_plan.lease_key())
                        .expect("prepared capability checkpoint");
                    rollback_verified &= self
                        .restore_capability(checkpoint)
                        .await
                        .is_ok_and(|report| report.verified);
                }
                if rollback_verified {
                    if !self.abandon_start_core(started_core).await {
                        stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
                        stored = self
                            .checkpoint_store
                            .replace(stored.revision, stored.checkpoint.clone())
                            .await
                            .unwrap_or(stored);
                        self.retain_recovery(grant, stored);
                        return Err(RuntimeStartError::Cleanup(
                            "failed start could not stop the Core it started".into(),
                        ));
                    }
                    if let Some(value) = grant.take() {
                        if let Err(error) = self.lease_coordinator.begin_release(&value) {
                            self.retain_recovery(Some(value), stored);
                            return Err(RuntimeStartError::Cleanup(error.to_string()));
                        }
                        if let Err(error) = self
                            .checkpoint_store
                            .delete(stored.checkpoint.id, stored.revision)
                            .await
                        {
                            self.retain_recovery(Some(value), stored);
                            return Err(RuntimeStartError::Store(error));
                        }
                        if let Err(error) = self
                            .lease_coordinator
                            .release(&value, LeaseReleaseEvidence::VerifiedRestore)
                        {
                            let message = error.to_string();
                            let (stored, store_error) =
                                self.recreate_deleted_checkpoint(stored).await;
                            self.retain_recovery(Some(value), stored);
                            return Err(RuntimeStartError::Cleanup(store_error.map_or(
                                message.clone(),
                                |store_error| {
                                    format!(
                                        "{message}; failed to recreate recovery checkpoint: {store_error}"
                                    )
                                },
                            )));
                        }
                    } else if let Err(error) = self
                        .checkpoint_store
                        .delete(stored.checkpoint.id, stored.revision)
                        .await
                    {
                        self.retain_recovery(None, stored);
                        return Err(RuntimeStartError::Store(error));
                    }
                    self.set_state(RuntimeState::Created);
                    return Err(RuntimeStartError::Capability(apply_error));
                } else {
                    stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
                    let stored = match self
                        .checkpoint_store
                        .replace(stored.revision, stored.checkpoint.clone())
                        .await
                    {
                        Ok(value) => value,
                        Err(error) => {
                            self.retain_recovery(grant, stored);
                            return Err(RuntimeStartError::Store(error));
                        }
                    };
                    if let Some(value) = grant.as_ref() {
                        if let Err(error) = self
                            .lease_coordinator
                            .mark_recovery_required(value, stored.checkpoint.id)
                        {
                            self.retain_recovery(grant, stored);
                            return Err(RuntimeStartError::Cleanup(error.to_string()));
                        }
                    }
                    let mut control = self.control.lock().expect("runtime control mutex");
                    control.state = RuntimeState::Degraded;
                    control.lease_grant = grant;
                    control.checkpoint = Some(stored);
                    return Err(RuntimeStartError::RecoveryRequired(apply_error));
                }
            }
        }

        let mut control = self.control.lock().expect("runtime control mutex");
        control.generation = stored.checkpoint.generation;
        control.state = RuntimeState::Running;
        control.lease_grant = grant;
        control.checkpoint = Some(stored.clone());
        let mut resources = RuntimeDomainReport::default();
        if started_core.is_some() {
            resources.push(RuntimeResourceChange::new(
                RuntimeResource::Core,
                RuntimeResourceOutcome::Applied,
            ));
        }
        for plan in &plans {
            resources.push(resource_change(plan, RuntimeResourceOutcome::Applied));
        }
        Ok(RuntimeStartReport {
            generation: control.generation,
            changed: true,
            checkpoint_id: Some(stored.checkpoint.id),
            resources,
        })
    }

    /// Destinations routed outside the tunnel must leave the capture's own
    /// addresses and the Core's fake-IP pool inside it. Checked before the
    /// routes are prepared.
    pub(super) fn validate_excluded_prefixes(
        &self,
        capability: crate::CapabilityKind,
        prefixes: &[crate::IpPrefix],
    ) -> Result<(), CapabilityError> {
        if prefixes.is_empty() {
            return Ok(());
        }
        let invalid = |message: String| {
            CapabilityError::new(
                capability,
                crate::CapabilityErrorCode::InvalidRequest,
                message,
            )
        };
        let reserved = self
            .ports
            .packet_capture
            .as_ref()
            .map(|capture| capture.reserved_addresses())
            .unwrap_or_default();
        for prefix in prefixes {
            if let Some(address) = reserved.iter().find(|address| prefix.contains(**address)) {
                return Err(invalid(format!(
                    "excluded prefix {prefix} covers the capture address {address}"
                )));
            }
        }
        match self.core.packet_device() {
            Some(core) => core
                .validate_excluded_destinations(
                    prefixes
                        .iter()
                        .map(|prefix| (prefix.address, prefix.prefix_len)),
                )
                .map_err(invalid),
            None => Ok(()),
        }
    }

    /// Checked before any OS mutation, whether TUN starts with the Core or is
    /// added to a running one.
    pub(super) fn validate_capture_addresses(&self) -> Result<(), CapabilityError> {
        let reserved = self
            .ports
            .packet_capture
            .as_ref()
            .map(|capture| capture.reserved_addresses())
            .unwrap_or_default();
        let Some(core) = self.core.packet_device() else {
            return Ok(());
        };
        core.validate_capture_addresses(&reserved)
            .map_err(|message| {
                packet_capability_error(crate::CapabilityErrorCode::InvalidRequest, message)
            })
    }
}
