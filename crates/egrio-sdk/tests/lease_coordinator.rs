use egrio_runtime::{
    CheckpointId, LeaseCoordinator, LeaseExpandError, LeaseReleaseEvidence, LeaseRequestSet,
    PlatformLeaseKey, PlatformLeaseState, RuntimeId,
};
use egrio_sdk::PlatformLeaseCoordinator;
use uuid::Uuid;

fn runtime(value: u128) -> RuntimeId {
    RuntimeId::from_uuid(Uuid::from_u128(value))
}
fn request(owner: RuntimeId, keys: Vec<PlatformLeaseKey>) -> LeaseRequestSet {
    LeaseRequestSet::new(owner, keys).unwrap()
}
#[test]
fn conflicting_acquire_fails_without_modifying_other_keys() {
    let coordinator = PlatformLeaseCoordinator::new();
    let first = coordinator
        .acquire_all(request(runtime(1), vec![PlatformLeaseKey::system_proxy()]))
        .unwrap();
    let conflict = coordinator
        .acquire_all(request(
            runtime(2),
            vec![
                PlatformLeaseKey::default_route(),
                PlatformLeaseKey::system_proxy(),
            ],
        ))
        .unwrap_err();
    assert_eq!(conflict.current_owner, Some(runtime(1)));
    assert_eq!(conflict.state, PlatformLeaseState::Held);
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(first.owner(), runtime(1));
}

#[test]
fn non_overlapping_leases_coexist() {
    let coordinator = PlatformLeaseCoordinator::new();
    coordinator
        .acquire_all(request(runtime(1), vec![PlatformLeaseKey::system_proxy()]))
        .unwrap();
    coordinator
        .acquire_all(request(runtime(2), vec![PlatformLeaseKey::default_route()]))
        .unwrap();
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).owner,
        Some(runtime(1))
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).owner,
        Some(runtime(2))
    );
}

#[test]
fn verified_shrink_releases_only_removed_keys_and_reissues_the_grant() {
    let coordinator = PlatformLeaseCoordinator::new();
    let grant = coordinator
        .acquire_all(request(
            runtime(3),
            vec![
                PlatformLeaseKey::default_route(),
                PlatformLeaseKey::system_proxy(),
            ],
        ))
        .unwrap();

    let replacement = coordinator
        .shrink(
            &grant,
            vec![PlatformLeaseKey::default_route()],
            LeaseReleaseEvidence::VerifiedRestore,
        )
        .unwrap();

    assert_ne!(replacement.id(), grant.id());
    assert_eq!(replacement.keys(), &[PlatformLeaseKey::default_route()]);
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Held
    );
    coordinator.begin_release(&replacement).unwrap();
    coordinator
        .release(&replacement, LeaseReleaseEvidence::VerifiedRestore)
        .unwrap();
}

#[test]
fn expand_reissues_one_grant_and_conflicts_atomically() {
    let coordinator = PlatformLeaseCoordinator::new();
    let grant = coordinator
        .acquire_all(request(runtime(4), vec![PlatformLeaseKey::system_dns()]))
        .unwrap();
    let blocker = coordinator
        .acquire_all(request(runtime(5), vec![PlatformLeaseKey::system_proxy()]))
        .unwrap();

    let error = coordinator
        .expand(
            &grant,
            request(
                runtime(4),
                vec![
                    PlatformLeaseKey::default_route(),
                    PlatformLeaseKey::system_dns(),
                    PlatformLeaseKey::system_proxy(),
                ],
            ),
        )
        .unwrap_err();
    assert!(matches!(error, LeaseExpandError::Conflict(_)));
    assert_eq!(grant.keys(), &[PlatformLeaseKey::system_dns()]);
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );

    coordinator
        .release(&blocker, LeaseReleaseEvidence::NoModification)
        .unwrap();
    let replacement = coordinator
        .expand(
            &grant,
            request(
                runtime(4),
                vec![
                    PlatformLeaseKey::default_route(),
                    PlatformLeaseKey::system_dns(),
                ],
            ),
        )
        .unwrap();

    assert_ne!(replacement.id(), grant.id());
    assert_eq!(
        replacement.keys(),
        &[
            PlatformLeaseKey::system_dns(),
            PlatformLeaseKey::default_route(),
        ]
    );
    assert!(coordinator.begin_release(&grant).is_err());
}

#[test]
fn no_modification_shrink_discards_only_newly_reserved_keys() {
    let coordinator = PlatformLeaseCoordinator::new();
    let original = coordinator
        .acquire_all(request(runtime(6), vec![PlatformLeaseKey::system_proxy()]))
        .unwrap();
    let expanded = coordinator
        .expand(
            &original,
            request(
                runtime(6),
                vec![
                    PlatformLeaseKey::system_proxy(),
                    PlatformLeaseKey::default_route(),
                ],
            ),
        )
        .unwrap();

    let restored = coordinator
        .shrink(
            &expanded,
            vec![PlatformLeaseKey::system_proxy()],
            LeaseReleaseEvidence::NoModification,
        )
        .unwrap();

    assert_eq!(restored.keys(), &[PlatformLeaseKey::system_proxy()]);
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::default_route()).state,
        PlatformLeaseState::Available
    );
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_proxy()).state,
        PlatformLeaseState::Held
    );
}

#[test]
fn dropping_a_grant_does_not_release_it() {
    let coordinator = PlatformLeaseCoordinator::new();
    {
        let _grant = coordinator
            .acquire_all(request(runtime(1), vec![PlatformLeaseKey::system_dns()]))
            .unwrap();
    }
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::system_dns()).state,
        PlatformLeaseState::Held
    );
}

#[test]
fn verified_release_makes_the_key_available_exactly_once() {
    let coordinator = PlatformLeaseCoordinator::new();
    let grant = coordinator
        .acquire_all(request(runtime(1), vec![PlatformLeaseKey::kill_switch()]))
        .unwrap();
    coordinator.begin_release(&grant).unwrap();
    coordinator
        .release(&grant, LeaseReleaseEvidence::VerifiedRestore)
        .unwrap();
    assert_eq!(
        coordinator.status(&PlatformLeaseKey::kill_switch()).state,
        PlatformLeaseState::Available
    );
    coordinator
        .acquire_all(request(runtime(2), vec![PlatformLeaseKey::kill_switch()]))
        .unwrap();
}

#[test]
fn recovery_required_blocks_until_verified_recovery() {
    let coordinator = PlatformLeaseCoordinator::new();
    let grant = coordinator
        .acquire_all(request(runtime(1), vec![PlatformLeaseKey::system_proxy()]))
        .unwrap();
    let checkpoint = CheckpointId::from_uuid(Uuid::from_u128(20));
    coordinator
        .mark_recovery_required(&grant, checkpoint)
        .unwrap();
    let conflict = coordinator
        .acquire_all(request(runtime(2), vec![PlatformLeaseKey::system_proxy()]))
        .unwrap_err();
    assert_eq!(conflict.state, PlatformLeaseState::RecoveryRequired);
    assert_eq!(conflict.checkpoint_id, Some(checkpoint));
    coordinator.begin_recovery(&grant).unwrap();
    coordinator.begin_recovery(&grant).unwrap();
    coordinator
        .release(&grant, LeaseReleaseEvidence::VerifiedRestore)
        .unwrap();
    coordinator
        .acquire_all(request(runtime(2), vec![PlatformLeaseKey::system_proxy()]))
        .unwrap();
}
