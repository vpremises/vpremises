use crate::support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{IncidentCoordinator, IncidentEventKindV1, IncidentPhase};

use support::{
    authorize_recovery, begin_containment, coordinator, definition, event, reach_recovery_pending,
    receipt, recovery_approval, submit_verified,
};

#[test]
fn all_definitive_containment_failures_enter_failed_phase() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "failed");
    for (index, command) in commands.iter().enumerate() {
        submit(
            &mut coordinator,
            command,
            &format!("failed.{index}"),
            EnforcementOutcome::Failed,
            &format!("2026-07-01T00:01:1{index}.000Z"),
        );
    }
    coordinator
        .apply_simulation(&event(
            "failed.finalize",
            1,
            "2026-07-01T00:01:12.000Z",
            IncidentEventKindV1::FinalizeContainment,
        ))
        .expect("finalize failed containment");
    assert_eq!(
        coordinator.snapshot().phase,
        IncidentPhase::ContainmentFailed
    );
}

fn submit(
    coordinator: &mut IncidentCoordinator,
    command: &crowsi_incident_coordinator::CoordinatorCommandV1,
    id: &str,
    outcome: EnforcementOutcome,
    occurred_at: &str,
) {
    if outcome == EnforcementOutcome::Applied {
        submit_verified(coordinator, command, id, outcome, occurred_at);
        return;
    }
    let wrapped = receipt(command, id, outcome);
    coordinator
        .apply_simulation(&event(
            id,
            command.isolation_epoch,
            occurred_at,
            IncidentEventKindV1::SubmitReceipt {
                receipt: Box::new(wrapped),
            },
        ))
        .expect("record receipt");
}

#[path = "failure_states/restoration.rs"]
mod restoration;
