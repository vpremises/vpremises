use crate::support;

use crowsi_incident_coordinator::{IncidentCoordinator, IncidentEventKindV1};

use support::{
    anchor, checkpoint, coordinator, current_head, definition, event, restore_challenge, trust,
    trust_digest,
};

#[test]
fn signed_checkpoint_cannot_override_initial_phase_invariants() {
    let mut coordinator = coordinator(definition());
    coordinator
        .apply_simulation(&event(
            "checkpoint.invariant.triage",
            0,
            "2026-07-01T00:01:00.000Z",
            IncidentEventKindV1::BeginTriage,
        ))
        .expect("triage");
    let clean = coordinator.export_state();

    let mut attempt = clean.clone();
    attempt.snapshot.restore_attempt = 99;
    let signed_attempt = checkpoint(&attempt, 1, None);
    let attempt_challenge = restore_challenge();
    let attempt_anchor = anchor(&signed_attempt, &attempt_challenge);
    assert!(
        IncidentCoordinator::restore_authenticated(
            attempt,
            &signed_attempt,
            &attempt_anchor,
            attempt_challenge,
            &trust_digest(),
            trust(),
            &current_head(&signed_attempt),
        )
        .is_err()
    );

    let mut replay = clean;
    replay
        .seen_evidence_jtis
        .insert("jti.invariant.injected".to_owned());
    let signed_replay = checkpoint(&replay, 1, None);
    let replay_challenge = restore_challenge();
    let replay_anchor = anchor(&signed_replay, &replay_challenge);
    assert!(
        IncidentCoordinator::restore_authenticated(
            replay,
            &signed_replay,
            &replay_anchor,
            replay_challenge,
            &trust_digest(),
            trust(),
            &current_head(&signed_replay),
        )
        .is_err()
    );
}
