use crate::support;

use crowsi_incident_coordinator::{IncidentCanonicalPayloadV1, IncidentCoordinator};

use support::{
    anchor, checkpoint, coordinator, current_head, definition, restore_challenge, sign_checkpoint,
    trust, trust_digest,
};

#[test]
fn monotonic_anchor_requires_its_own_valid_signature() {
    let state = coordinator(definition()).export_state();
    let checkpoint = checkpoint(&state, 1, None);
    let forged_challenge = restore_challenge();
    let mut forged = anchor(&checkpoint, &forged_challenge);
    let replacement = if forged.signed.signature.starts_with('A') {
        "B"
    } else {
        "A"
    };
    forged.signed.signature.replace_range(0..1, replacement);
    assert!(
        IncidentCoordinator::restore_authenticated(
            state.clone(),
            &checkpoint,
            &forged,
            forged_challenge,
            &trust_digest(),
            trust(),
            &current_head(&checkpoint),
        )
        .is_err()
    );

    let confused_challenge = restore_challenge();
    let mut role_confused = anchor(&checkpoint, &confused_challenge);
    role_confused.signed = sign_checkpoint(&role_confused.signing_payload());
    assert!(
        IncidentCoordinator::restore_authenticated(
            state,
            &checkpoint,
            &role_confused,
            confused_challenge,
            &trust_digest(),
            trust(),
            &current_head(&checkpoint),
        )
        .is_err()
    );
}

#[test]
fn restore_requires_the_locally_configured_deployment() {
    let state = coordinator(definition()).export_state();
    let checkpoint = checkpoint(&state, 1, None);
    let challenge = IncidentCoordinator::begin_authenticated_restore(
        "deployment.other",
        &state.snapshot.incident_id,
    )
    .expect("other deployment challenge");
    let signed_anchor = anchor(&checkpoint, &challenge);
    assert!(
        IncidentCoordinator::restore_authenticated(
            state,
            &checkpoint,
            &signed_anchor,
            challenge,
            &trust_digest(),
            trust(),
            &current_head(&checkpoint),
        )
        .is_err()
    );
}

#[test]
fn old_anchor_cannot_answer_a_fresh_restore_challenge() {
    let state = coordinator(definition()).export_state();
    let checkpoint = checkpoint(&state, 1, None);
    let old_challenge = restore_challenge();
    let old_anchor = anchor(&checkpoint, &old_challenge);
    IncidentCoordinator::restore_authenticated(
        state.clone(),
        &checkpoint,
        &old_anchor,
        old_challenge,
        &trust_digest(),
        trust(),
        &current_head(&checkpoint),
    )
    .expect("first fresh challenge");
    let fresh_challenge = restore_challenge();
    assert!(
        IncidentCoordinator::restore_authenticated(
            state,
            &checkpoint,
            &old_anchor,
            fresh_challenge,
            &trust_digest(),
            trust(),
            &current_head(&checkpoint),
        )
        .is_err()
    );
}
