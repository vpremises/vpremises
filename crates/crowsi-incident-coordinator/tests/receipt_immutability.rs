use crate::support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{
    IncidentCoordinator, IncidentEventKindV1, IndependentObservedOutcome, ObservedTargetState,
};

use support::{begin_containment, coordinator, definition, event, receipt, verification};

#[test]
fn caller_cannot_promote_applied_receipt_without_independent_signature() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "untrusted");
    let wrapped = receipt(
        &commands[0],
        "untrusted.applied",
        EnforcementOutcome::Applied,
    );
    submit_receipt(
        &mut coordinator,
        "untrusted.receipt",
        "2026-07-01T00:01:10.000Z",
        wrapped.clone(),
    )
    .expect("signed PEP receipt");
    assert_eq!(
        coordinator.snapshot().targets[&wrapped.target_id].observed,
        ObservedTargetState::Unknown
    );
    let mut forged = verification(
        &wrapped,
        "untrusted.forged",
        IndependentObservedOutcome::Applied,
    );
    forged.signed.signature.replace_range(0..1, "A");
    let before = coordinator.snapshot().clone();
    assert!(
        submit_verification(
            &mut coordinator,
            "untrusted.forged",
            "2026-07-01T00:01:11.000Z",
            forged,
        )
        .is_err()
    );
    assert_eq!(coordinator.snapshot(), &before);
    submit_verification(
        &mut coordinator,
        "untrusted.valid",
        "2026-07-01T00:01:12.000Z",
        verification(
            &wrapped,
            "untrusted.valid",
            IndependentObservedOutcome::Applied,
        ),
    )
    .expect("trusted independent evidence");
}

#[test]
fn a_second_receipt_for_one_command_is_rejected() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "conflict");
    let original = receipt(
        &commands[0],
        "conflict.original",
        EnforcementOutcome::Failed,
    );
    submit_receipt(
        &mut coordinator,
        "conflict.submit",
        "2026-07-01T00:01:10.000Z",
        original,
    )
    .expect("first receipt");
    let snapshot = coordinator.snapshot().clone();
    let conflicting = receipt(&commands[0], "conflict.second", EnforcementOutcome::Applied);
    assert!(
        submit_receipt(
            &mut coordinator,
            "conflict.replace",
            "2026-07-01T00:01:11.000Z",
            conflicting,
        )
        .is_err()
    );
    assert_eq!(coordinator.snapshot(), &snapshot);
}

fn submit_receipt(
    coordinator: &mut IncidentCoordinator,
    event_id: &str,
    occurred_at: &str,
    wrapped: crowsi_incident_coordinator::CoordinatorReceiptV1,
) -> Result<Vec<crowsi_incident_coordinator::CoordinatorCommandV1>, impl std::error::Error> {
    coordinator.apply_simulation(&event(
        event_id,
        wrapped.isolation_epoch,
        occurred_at,
        IncidentEventKindV1::SubmitReceipt {
            receipt: Box::new(wrapped),
        },
    ))
}

fn submit_verification(
    coordinator: &mut IncidentCoordinator,
    event_id: &str,
    occurred_at: &str,
    evidence: crowsi_incident_coordinator::IndependentVerificationArtifactV1,
) -> Result<Vec<crowsi_incident_coordinator::CoordinatorCommandV1>, impl std::error::Error> {
    coordinator.apply_simulation(&event(
        event_id,
        evidence.isolation_epoch,
        occurred_at,
        IncidentEventKindV1::SubmitVerification {
            verification: Box::new(evidence),
        },
    ))
}
