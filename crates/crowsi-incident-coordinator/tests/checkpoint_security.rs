use crate::support;

use crowsi_incident_coordinator::{
    IncidentCanonicalPayloadV1, IncidentCoordinator, IncidentEventKindV1,
};

use support::{
    anchor, checkpoint, coordinator, current_head, definition, event, restore_challenge, trust,
    trust_digest, trust_with_foreign_owner,
};

#[test]
fn external_anchor_rejects_rollback_and_runtime_rejects_branching() {
    let mut coordinator = coordinator(definition());
    let initial = coordinator.export_state();
    let first = checkpoint(&initial, 1, None);
    coordinator
        .apply_simulation(&event(
            "checkpoint.triage",
            0,
            "2026-07-01T00:01:00.000Z",
            IncidentEventKindV1::BeginTriage,
        ))
        .expect("triage");
    let triage = coordinator.export_state();
    let second = checkpoint(&triage, 2, Some(first.payload_digest()));
    let rollback_challenge = restore_challenge();
    let rollback_anchor = anchor(&first, &rollback_challenge);
    assert!(
        IncidentCoordinator::restore_authenticated(
            initial,
            &first,
            &rollback_anchor,
            rollback_challenge,
            &trust_digest(),
            trust(),
            &current_head(&second),
        )
        .is_err()
    );
    let latest_challenge = restore_challenge();
    let latest_anchor = anchor(&second, &latest_challenge);
    let mut restored = IncidentCoordinator::restore_authenticated(
        triage,
        &second,
        &latest_anchor,
        latest_challenge,
        &trust_digest(),
        trust(),
        &current_head(&second),
    )
    .expect("latest anchored checkpoint");
    let branch = checkpoint(&restored.export_state(), 1, None);
    let branch_challenge = restored
        .checkpoint_commit_challenge()
        .expect("branch challenge");
    let branch_anchor = anchor(&branch, &branch_challenge);
    assert!(
        restored
            .confirm_checkpoint_commit(
                &branch,
                &branch_anchor,
                branch_challenge,
                &current_head(&branch),
            )
            .is_err()
    );
    let third = checkpoint(&restored.export_state(), 3, Some(second.payload_digest()));
    let third_challenge = restored
        .checkpoint_commit_challenge()
        .expect("third challenge");
    let third_anchor = anchor(&third, &third_challenge);
    restored
        .confirm_checkpoint_commit(
            &third,
            &third_anchor,
            third_challenge,
            &current_head(&third),
        )
        .expect("exact next checkpoint");
    assert!(!restored.checkpoint_required());
}

#[test]
fn bootstrap_trust_pin_rejects_self_consistent_substitution_and_revision_change() {
    let alternate_trust = trust_with_foreign_owner();
    let alternate = IncidentCoordinator::new_simulation(definition(), alternate_trust.clone())
        .expect("alternate simulation");
    let state = alternate.export_state();
    let checkpoint = checkpoint(&state, 1, None);
    let challenge = restore_challenge();
    let signed_anchor = anchor(&checkpoint, &challenge);
    assert!(
        IncidentCoordinator::restore_authenticated(
            state,
            &checkpoint,
            &signed_anchor,
            challenge,
            &trust_digest(),
            alternate_trust,
            &current_head(&checkpoint),
        )
        .is_err()
    );

    let original_state = coordinator(definition()).export_state();
    let mut revised = trust();
    revised.revision = 2;
    assert!(IncidentCoordinator::restore_simulation(original_state, revised).is_err());
}
