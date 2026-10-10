use crate::support;

use crowsi_incident_coordinator::{
    IncidentCanonicalPayloadV1, IncidentCoordinator, IncidentEventKindV1,
};

use support::{
    anchor, checkpoint, containment_authorizations, current_head, definition, event, system_now,
    trust, trust_digest,
};

#[test]
fn production_owns_clock_and_gates_every_uncheckpointed_transition() {
    let definition = definition();
    let mut coordinator = IncidentCoordinator::new(definition.clone(), trust(), &trust_digest())
        .expect("production coordinator");
    let first = checkpoint(&coordinator.export_state(), 1, None);
    let first_challenge = coordinator
        .checkpoint_commit_challenge()
        .expect("initial checkpoint challenge");
    let first_anchor = anchor(&first, &first_challenge);
    coordinator
        .confirm_checkpoint_commit(
            &first,
            &first_anchor,
            first_challenge,
            &current_head(&first),
        )
        .expect("initial durable commit");
    let issued_at = system_now();
    let triage = event(
        "production.triage",
        0,
        &issued_at,
        IncidentEventKindV1::BeginTriage,
    );
    coordinator.apply(&triage).expect("fresh production event");
    assert!(coordinator.checkpoint_required());
    assert!(coordinator.snapshot().trusted_time_watermark >= issued_at);
    assert!(coordinator.apply(&triage).is_err());

    let second = checkpoint(&coordinator.export_state(), 2, Some(first.payload_digest()));
    let second_challenge = coordinator
        .checkpoint_commit_challenge()
        .expect("transition checkpoint challenge");
    let second_anchor = anchor(&second, &second_challenge);
    coordinator
        .confirm_checkpoint_commit(
            &second,
            &second_anchor,
            second_challenge,
            &current_head(&second),
        )
        .expect("transition commit");
    let expired = event(
        "production.expired",
        0,
        "2026-07-01T00:01:05.000Z",
        IncidentEventKindV1::RequestContainment {
            authorizations: containment_authorizations(&definition, "production.expired"),
        },
    );
    let before = coordinator.export_state();
    assert!(coordinator.apply(&expired).is_err());
    assert_eq!(coordinator.export_state(), before);
}
