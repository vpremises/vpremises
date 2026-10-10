use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{
    CoordinatorCommandV1, IncidentCoordinator, IncidentDefinitionV1, IncidentEventKindV1,
    IndependentObservedOutcome,
};

use super::{containment_authorizations, event, receipt, recovery_approval, verification};

pub fn authorize_recovery(
    coordinator: &mut IncidentCoordinator,
    definition: &IncidentDefinitionV1,
    tag: &str,
    event_id: &str,
) {
    coordinator
        .apply_simulation(&event(
            event_id,
            1,
            "2026-07-01T00:02:05.000Z",
            IncidentEventKindV1::AuthorizeRecovery {
                approval: Box::new(recovery_approval(definition, tag)),
            },
        ))
        .expect("authorize recovery");
}

pub fn begin_containment(
    coordinator: &mut IncidentCoordinator,
    definition: &IncidentDefinitionV1,
    tag: &str,
) -> Vec<CoordinatorCommandV1> {
    coordinator
        .apply_simulation(&event(
            &format!("{tag}.triage"),
            0,
            "2026-07-01T00:01:00.000Z",
            IncidentEventKindV1::BeginTriage,
        ))
        .expect("begin triage");
    coordinator
        .apply_simulation(&event(
            &format!("{tag}.contain"),
            0,
            "2026-07-01T00:01:05.000Z",
            IncidentEventKindV1::RequestContainment {
                authorizations: containment_authorizations(definition, tag),
            },
        ))
        .expect("request containment")
}

pub fn reach_recovery_pending(
    coordinator: &mut IncidentCoordinator,
    definition: &IncidentDefinitionV1,
    tag: &str,
) {
    let commands = begin_containment(coordinator, definition, tag);
    for (index, command) in commands.iter().enumerate() {
        submit_verified(
            coordinator,
            command,
            &format!("{tag}.contain.{index}"),
            EnforcementOutcome::Applied,
            &format!("2026-07-01T00:01:1{index}.000Z"),
        );
    }
    coordinator
        .apply_simulation(&event(
            &format!("{tag}.finalize"),
            1,
            "2026-07-01T00:01:20.000Z",
            IncidentEventKindV1::FinalizeContainment,
        ))
        .expect("finalize containment");
    coordinator
        .apply_simulation(&event(
            &format!("{tag}.eradicate"),
            1,
            "2026-07-01T00:01:30.000Z",
            IncidentEventKindV1::BeginEradication,
        ))
        .expect("begin eradication");
    coordinator
        .apply_simulation(&event(
            &format!("{tag}.recovery"),
            1,
            "2026-07-01T00:01:40.000Z",
            IncidentEventKindV1::RequestRecovery,
        ))
        .expect("request recovery");
}

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
