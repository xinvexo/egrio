use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use egrio_runtime::{
    CheckpointId, LeaseCoordinator, LeaseExpandError, LeaseGrant, LeaseGrantId, LeaseGrantSecret,
    LeaseReleaseEvidence, LeaseRequestSet, LeaseTransitionError, LeaseTransitionErrorCode,
    PlatformLeaseConflict, PlatformLeaseKey, PlatformLeaseState, RuntimeId, StoredCheckpoint,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformLeaseStatus {
    pub state: PlatformLeaseState,
    pub owner: Option<RuntimeId>,
    pub checkpoint_id: Option<CheckpointId>,
}

#[derive(Debug)]
pub struct RecoveryReservationError {
    pub conflict: PlatformLeaseConflict,
}

#[derive(Debug)]
struct LeaseRecord {
    grant_id: LeaseGrantId,
    owner: RuntimeId,
    state: PlatformLeaseState,
    checkpoint_id: Option<CheckpointId>,
}

#[derive(Clone, Debug)]
struct GrantRecord {
    owner: RuntimeId,
    keys: Vec<PlatformLeaseKey>,
    secret: LeaseGrantSecret,
}

#[derive(Debug, Default)]
struct CoordinatorState {
    leases: BTreeMap<PlatformLeaseKey, LeaseRecord>,
    grants: HashMap<LeaseGrantId, GrantRecord>,
}

#[derive(Debug, Default)]
pub struct PlatformLeaseCoordinator {
    inner: Mutex<CoordinatorState>,
}

impl PlatformLeaseCoordinator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn status(&self, key: &PlatformLeaseKey) -> PlatformLeaseStatus {
        let state = self.inner.lock().expect("lease coordinator mutex");
        match state.leases.get(key) {
            Some(record) => PlatformLeaseStatus {
                state: record.state,
                owner: Some(record.owner),
                checkpoint_id: record.checkpoint_id,
            },
            None => PlatformLeaseStatus {
                state: PlatformLeaseState::Available,
                owner: None,
                checkpoint_id: None,
            },
        }
    }

    #[doc(hidden)]
    pub(crate) fn reserve_recovery_batch(
        &self,
        checkpoints: &[StoredCheckpoint],
    ) -> Result<Vec<LeaseGrant>, RecoveryReservationError> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let mut batch_keys = BTreeMap::<PlatformLeaseKey, (RuntimeId, CheckpointId)>::new();

        for stored in checkpoints {
            let checkpoint = &stored.checkpoint;
            for key in &checkpoint.leases {
                if let Some(record) = state.leases.get(key) {
                    let conflict = conflict(key.clone(), checkpoint.runtime_id, record);
                    poison_recovery_keys(&mut state, checkpoints);
                    return Err(RecoveryReservationError { conflict });
                }
                if let Some((owner, checkpoint_id)) = batch_keys.get(key) {
                    poison_recovery_keys(&mut state, checkpoints);
                    return Err(RecoveryReservationError {
                        conflict: PlatformLeaseConflict {
                            requested: key.clone(),
                            requested_by: checkpoint.runtime_id,
                            current_owner: Some(*owner),
                            state: PlatformLeaseState::RecoveryRequired,
                            external_owner: None,
                            checkpoint_id: Some(*checkpoint_id),
                        },
                    });
                }
                batch_keys.insert(key.clone(), (checkpoint.runtime_id, checkpoint.id));
            }
        }

        let mut grants = Vec::with_capacity(checkpoints.len());
        for stored in checkpoints {
            let checkpoint = &stored.checkpoint;
            let keys = checkpoint.leases.clone();
            let (grant, secret) = LeaseGrant::issue(checkpoint.runtime_id, keys.clone());
            let grant_id = grant.id();
            for key in &keys {
                state.leases.insert(
                    key.clone(),
                    LeaseRecord {
                        grant_id,
                        owner: checkpoint.runtime_id,
                        state: PlatformLeaseState::RecoveryRequired,
                        checkpoint_id: Some(checkpoint.id),
                    },
                );
            }
            state.grants.insert(
                grant_id,
                GrantRecord {
                    owner: checkpoint.runtime_id,
                    keys: keys.clone(),
                    secret,
                },
            );
            grants.push(grant);
        }
        Ok(grants)
    }

    fn validate_grant<'a>(
        state: &'a CoordinatorState,
        grant: &LeaseGrant,
    ) -> Result<&'a GrantRecord, LeaseTransitionError> {
        let record = state.grants.get(&grant.id()).ok_or_else(|| {
            transition_error(
                LeaseTransitionErrorCode::UnknownGrant,
                "lease grant is not owned by this coordinator",
            )
        })?;
        if record.owner != grant.owner()
            || record.keys != grant.keys()
            || !grant.authenticates(record.secret)
        {
            return Err(transition_error(
                LeaseTransitionErrorCode::GrantMismatch,
                "lease grant owner or keys do not match coordinator state",
            ));
        }
        Ok(record)
    }
}

fn poison_recovery_keys(state: &mut CoordinatorState, checkpoints: &[StoredCheckpoint]) {
    for stored in checkpoints {
        for key in &stored.checkpoint.leases {
            state
                .leases
                .entry(key.clone())
                .or_insert_with(|| LeaseRecord {
                    grant_id: LeaseGrantId::new(),
                    owner: stored.checkpoint.runtime_id,
                    state: PlatformLeaseState::RecoveryRequired,
                    checkpoint_id: Some(stored.checkpoint.id),
                });
        }
    }
}

impl LeaseCoordinator for PlatformLeaseCoordinator {
    fn acquire_all(&self, request: LeaseRequestSet) -> Result<LeaseGrant, PlatformLeaseConflict> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        for key in request.keys() {
            if let Some(record) = state.leases.get(key) {
                return Err(conflict(key.clone(), request.owner(), record));
            }
        }
        let owner = request.owner();
        let keys = request.keys().to_vec();
        let (grant, secret) = LeaseGrant::issue(owner, keys.clone());
        let grant_id = grant.id();
        for key in &keys {
            state.leases.insert(
                key.clone(),
                LeaseRecord {
                    grant_id,
                    owner,
                    state: PlatformLeaseState::Held,
                    checkpoint_id: None,
                },
            );
        }
        state.grants.insert(
            grant_id,
            GrantRecord {
                owner,
                keys: keys.clone(),
                secret,
            },
        );
        Ok(grant)
    }

    fn expand(
        &self,
        grant: &LeaseGrant,
        request: LeaseRequestSet,
    ) -> Result<LeaseGrant, LeaseExpandError> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let record = Self::validate_grant(&state, grant)
            .cloned()
            .map_err(LeaseExpandError::Transition)?;
        ensure_states(
            &state,
            grant.id(),
            &record.keys,
            &[PlatformLeaseState::Held],
        )
        .map_err(LeaseExpandError::Transition)?;
        if request.owner() != record.owner
            || request.keys().len() <= record.keys.len()
            || record.keys.iter().any(|key| !request.keys().contains(key))
        {
            return Err(LeaseExpandError::Transition(transition_error(
                LeaseTransitionErrorCode::GrantMismatch,
                "expanded lease keys must be a strict superset owned by the same runtime",
            )));
        }
        let added = request
            .keys()
            .iter()
            .filter(|key| !record.keys.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        for key in &added {
            if let Some(existing) = state.leases.get(key) {
                return Err(LeaseExpandError::Conflict(conflict(
                    key.clone(),
                    request.owner(),
                    existing,
                )));
            }
        }

        let keys = request.keys().to_vec();
        let (replacement, secret) = LeaseGrant::issue(record.owner, keys.clone());
        let replacement_id = replacement.id();
        for key in &record.keys {
            state
                .leases
                .get_mut(key)
                .expect("validated retained lease")
                .grant_id = replacement_id;
        }
        for key in added {
            state.leases.insert(
                key,
                LeaseRecord {
                    grant_id: replacement_id,
                    owner: record.owner,
                    state: PlatformLeaseState::Held,
                    checkpoint_id: None,
                },
            );
        }
        state.grants.remove(&grant.id());
        state.grants.insert(
            replacement_id,
            GrantRecord {
                owner: record.owner,
                keys,
                secret,
            },
        );
        Ok(replacement)
    }

    fn begin_release(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let keys = Self::validate_grant(&state, grant)?.keys.clone();
        ensure_states(&state, grant.id(), &keys, &[PlatformLeaseState::Held])?;
        set_state(
            &mut state,
            grant.id(),
            &keys,
            PlatformLeaseState::Releasing,
            None,
        );
        Ok(())
    }

    fn mark_recovery_required(
        &self,
        grant: &LeaseGrant,
        checkpoint_id: CheckpointId,
    ) -> Result<(), LeaseTransitionError> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let keys = Self::validate_grant(&state, grant)?.keys.clone();
        ensure_states(
            &state,
            grant.id(),
            &keys,
            &[
                PlatformLeaseState::Held,
                PlatformLeaseState::Releasing,
                PlatformLeaseState::Recovering,
            ],
        )?;
        set_state(
            &mut state,
            grant.id(),
            &keys,
            PlatformLeaseState::RecoveryRequired,
            Some(checkpoint_id),
        );
        Ok(())
    }

    fn begin_recovery(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let keys = Self::validate_grant(&state, grant)?.keys.clone();
        ensure_states(
            &state,
            grant.id(),
            &keys,
            &[
                PlatformLeaseState::RecoveryRequired,
                PlatformLeaseState::Recovering,
            ],
        )?;
        set_state(
            &mut state,
            grant.id(),
            &keys,
            PlatformLeaseState::Recovering,
            None,
        );
        Ok(())
    }

    fn resume(&self, grant: &LeaseGrant) -> Result<(), LeaseTransitionError> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let keys = Self::validate_grant(&state, grant)?.keys.clone();
        ensure_states(&state, grant.id(), &keys, &[PlatformLeaseState::Recovering])?;
        set_state(
            &mut state,
            grant.id(),
            &keys,
            PlatformLeaseState::Held,
            None,
        );
        Ok(())
    }

    fn shrink(
        &self,
        grant: &LeaseGrant,
        mut retained_keys: Vec<PlatformLeaseKey>,
        evidence: LeaseReleaseEvidence,
    ) -> Result<LeaseGrant, LeaseTransitionError> {
        if !matches!(
            evidence,
            LeaseReleaseEvidence::NoModification | LeaseReleaseEvidence::VerifiedRestore
        ) {
            return Err(transition_error(
                LeaseTransitionErrorCode::InvalidState,
                "partial lease release requires no-modification or verified-restore evidence",
            ));
        }
        retained_keys.sort();
        retained_keys.dedup();
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let record = Self::validate_grant(&state, grant)?.clone();
        ensure_states(
            &state,
            grant.id(),
            &record.keys,
            &[PlatformLeaseState::Held],
        )?;
        if retained_keys.is_empty()
            || retained_keys.len() >= record.keys.len()
            || retained_keys.iter().any(|key| !record.keys.contains(key))
        {
            return Err(transition_error(
                LeaseTransitionErrorCode::GrantMismatch,
                "retained lease keys must be a non-empty strict subset of the grant",
            ));
        }
        let removed = record
            .keys
            .iter()
            .filter(|key| !retained_keys.contains(key))
            .cloned()
            .collect::<Vec<_>>();
        let (replacement, secret) = LeaseGrant::issue(record.owner, retained_keys.clone());
        let replacement_id = replacement.id();
        for key in &removed {
            state.leases.remove(key);
        }
        for key in &retained_keys {
            let lease = state.leases.get_mut(key).ok_or_else(|| {
                transition_error(
                    LeaseTransitionErrorCode::GrantMismatch,
                    "retained lease disappeared during grant shrink",
                )
            })?;
            lease.grant_id = replacement_id;
        }
        state.grants.remove(&grant.id());
        state.grants.insert(
            replacement_id,
            GrantRecord {
                owner: record.owner,
                keys: retained_keys,
                secret,
            },
        );
        Ok(replacement)
    }

    fn release(
        &self,
        grant: &LeaseGrant,
        evidence: LeaseReleaseEvidence,
    ) -> Result<(), LeaseTransitionError> {
        let mut state = self.inner.lock().expect("lease coordinator mutex");
        let keys = Self::validate_grant(&state, grant)?.keys.clone();
        let allowed = match evidence {
            LeaseReleaseEvidence::NoModification => vec![PlatformLeaseState::Held],
            LeaseReleaseEvidence::VerifiedRestore => vec![
                PlatformLeaseState::Releasing,
                PlatformLeaseState::Recovering,
            ],
            LeaseReleaseEvidence::VerifiedAdoption => vec![PlatformLeaseState::Recovering],
            _ => {
                return Err(transition_error(
                    LeaseTransitionErrorCode::InvalidState,
                    "lease release evidence is not supported by this coordinator version",
                ))
            }
        };
        ensure_states(&state, grant.id(), &keys, &allowed)?;
        for key in &keys {
            state.leases.remove(key);
        }
        state.grants.remove(&grant.id());
        Ok(())
    }
}

fn conflict(
    requested: PlatformLeaseKey,
    requested_by: RuntimeId,
    record: &LeaseRecord,
) -> PlatformLeaseConflict {
    PlatformLeaseConflict {
        requested,
        requested_by,
        current_owner: Some(record.owner),
        state: record.state,
        external_owner: None,
        checkpoint_id: record.checkpoint_id,
    }
}

fn ensure_states(
    state: &CoordinatorState,
    grant_id: LeaseGrantId,
    keys: &[PlatformLeaseKey],
    allowed: &[PlatformLeaseState],
) -> Result<(), LeaseTransitionError> {
    let valid = keys.iter().all(|key| {
        state
            .leases
            .get(key)
            .is_some_and(|record| record.grant_id == grant_id && allowed.contains(&record.state))
    });
    if valid {
        Ok(())
    } else {
        Err(transition_error(
            LeaseTransitionErrorCode::InvalidState,
            "lease grant is not in a state accepted by this transition",
        ))
    }
}

fn set_state(
    state: &mut CoordinatorState,
    grant_id: LeaseGrantId,
    keys: &[PlatformLeaseKey],
    next: PlatformLeaseState,
    checkpoint_id: Option<CheckpointId>,
) {
    for key in keys {
        let record = state.leases.get_mut(key).expect("validated lease record");
        assert_eq!(record.grant_id, grant_id);
        record.state = next;
        if checkpoint_id.is_some() {
            record.checkpoint_id = checkpoint_id;
        }
    }
}

fn transition_error(
    code: LeaseTransitionErrorCode,
    message: impl Into<String>,
) -> LeaseTransitionError {
    LeaseTransitionError {
        code,
        message: message.into(),
    }
}
