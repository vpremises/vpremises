use crate::support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{
    DesiredTargetState, IncidentCoordinator, IncidentEventKindV1, IncidentPhase,
    IndependentObservedOutcome, ObservedTargetState, TransactionState,
};

use support::{TARGET, begin_containment, coordinator, definition, event, receipt, verification};

#[test]
fn target_and_incident_wait_for_every_verified_applied_receipt() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "complete");
    assert_eq!(commands.len(), 2);
    assert_eq!(coordinator.snapshot().isolation_epoch, 1);
    let target = &coordinator.snapshot().targets[TARGET];
    assert_eq!(target.desired, DesiredTargetState::Isolated);
    assert_eq!(target.observed, ObservedTargetState::Unknown);
    assert_eq!(target.transaction, TransactionState::Pending);
    submit(
        &mut coordinator,
        &commands[0],
        "complete.first",
        Some(IndependentObservedOutcome::Applied),
        EnforcementOutcome::Applied,
        "2026-07-01T00:01:10.000Z",
    );
    let target = &coordinator.snapshot().targets[TARGET];
    assert_eq!(target.observed, ObservedTargetState::Partial);
    assert_ne!(target.transaction, TransactionState::Verified);
    submit(
        &mut coordinator,
        &commands[1],
        "complete.second",
        Some(IndependentObservedOutcome::Applied),
        EnforcementOutcome::Applied,
        "2026-07-01T00:01:11.000Z",
    );
    assert_eq!(
        coordinator.snapshot().targets[TARGET].observed,
        ObservedTargetState::Isolated
    );
    assert_eq!(
        coordinator.snapshot().phase,
        IncidentPhase::ContainmentRequested
    );
    coordinator
        .apply_simulation(&event(
            "complete.finalize",
            1,
            "2026-07-01T00:01:12.000Z",
            IncidentEventKindV1::FinalizeContainment,
        ))
        .expect("finalize containment");
    assert_eq!(coordinator.snapshot().phase, IncidentPhase::Contained);
}

fn submit(
    coordinator: &mut IncidentCoordinator,
    command: &crowsi_incident_coordinator::CoordinatorCommandV1,
    id: &str,
    observation: Option<IndependentObservedOutcome>,
    outcome: EnforcementOutcome,
    time: &str,
) {
    let wrapped = receipt(command, id, outcome);
    coordinator
        .apply_simulation(&event(
            &format!("{id}.receipt"),
            command.isolation_epoch,
            time,
            IncidentEventKindV1::SubmitReceipt {
                receipt: Box::new(wrapped.clone()),
            },
        ))
        .expect("record receipt");
    if let Some(outcome) = observation {
        coordinator
            .apply_simulation(&event(
                &format!("{id}.verification"),
                command.isolation_epoch,
                time,
                IncidentEventKindV1::SubmitVerification {
                    verification: Box::new(verification(&wrapped, id, outcome)),
                },
            ))
            .expect("record independent verification");
    }
}

#[path = "containment_aggregation/partial_failure.rs"]
mod partial_failure;
