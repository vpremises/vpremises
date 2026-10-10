//! Regression coverage and synthetic evidence for verification boundaries.
use super::*;

pub fn submit_verified(
    coordinator: &mut IncidentCoordinator,
    command: &CoordinatorCommandV1,
    id: &str,
    outcome: EnforcementOutcome,
    occurred_at: &str,
) {
    let wrapped = receipt(command, id, outcome);
    let evidence = verification(&wrapped, id, IndependentObservedOutcome::Applied);
    coordinator
        .apply_simulation(&event(
            &format!("{id}.receipt"),
            command.isolation_epoch,
            occurred_at,
            IncidentEventKindV1::SubmitReceipt {
                receipt: Box::new(wrapped),
            },
        ))
        .expect("record PEP receipt");
    coordinator
        .apply_simulation(&event(
            &format!("{id}.verification"),
            command.isolation_epoch,
            occurred_at,
            IncidentEventKindV1::SubmitVerification {
                verification: Box::new(evidence),
            },
        ))
        .expect("record independent verification");
}
