use crate::support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{
    IncidentEventKindV1, IncidentPhase, IndependentObservedOutcome, ObservedTargetState,
};

use support::{TARGET, begin_containment, coordinator, definition, event, receipt, verification};

#[test]
fn unknown_verification_is_never_promoted_to_isolated() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "unknown");
    for (index, command) in commands.iter().enumerate() {
        let id = format!("unknown.{index}");
        let time = format!("2026-07-01T00:01:1{index}.000Z");
        let wrapped = receipt(command, &id, EnforcementOutcome::Applied);
        coordinator
            .apply_simulation(&event(
                &format!("{id}.receipt"),
                1,
                &time,
                IncidentEventKindV1::SubmitReceipt {
                    receipt: Box::new(wrapped.clone()),
                },
            ))
            .expect("record receipt");
        coordinator
            .apply_simulation(&event(
                &format!("{id}.verification"),
                1,
                &time,
                IncidentEventKindV1::SubmitVerification {
                    verification: Box::new(verification(
                        &wrapped,
                        &id,
                        IndependentObservedOutcome::Unknown,
                    )),
                },
            ))
            .expect("record unknown verification");
    }
    assert_eq!(
        coordinator.snapshot().targets[TARGET].observed,
        ObservedTargetState::Unknown
    );
    coordinator
        .apply_simulation(&event(
            "unknown.finalize",
            1,
            "2026-07-01T00:01:12.000Z",
            IncidentEventKindV1::FinalizeContainment,
        ))
        .expect("finalize unknown");
    assert_eq!(
        coordinator.snapshot().phase,
        IncidentPhase::ContainmentPartial
    );
}
