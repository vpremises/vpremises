use crate::support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{IncidentEventKindV1, IncidentPhase};

use support::{
    begin_containment, containment_authorizations, coordinator, definition, event, receipt,
};

#[test]
fn duplicate_events_are_rejected_and_exact_receipts_are_idempotent() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let triage = event(
        "replay.triage",
        0,
        "2026-07-01T00:01:00.000Z",
        IncidentEventKindV1::BeginTriage,
    );
    coordinator.apply_simulation(&triage).expect("first event");
    assert!(coordinator.apply_simulation(&triage).is_err());
    let commands = coordinator
        .apply_simulation(&event(
            "replay.contain",
            0,
            "2026-07-01T00:01:05.000Z",
            IncidentEventKindV1::RequestContainment {
                authorizations: containment_authorizations(&definition, "replay"),
            },
        ))
        .expect("containment");
    let wrapped = receipt(&commands[0], "replay.receipt", EnforcementOutcome::Applied);
    coordinator
        .apply_simulation(&event(
            "replay.receipt.event.1",
            1,
            "2026-07-01T00:01:10.000Z",
            IncidentEventKindV1::SubmitReceipt {
                receipt: Box::new(wrapped.clone()),
            },
        ))
        .expect("first receipt");
    coordinator
        .apply_simulation(&event(
            "replay.receipt.event.2",
            1,
            "2026-07-01T00:01:11.000Z",
            IncidentEventKindV1::SubmitReceipt {
                receipt: Box::new(wrapped.clone()),
            },
        ))
        .expect("exact receipt replay is idempotent");
    let target = coordinator
        .snapshot()
        .targets
        .get(&wrapped.target_id)
        .expect("target");
    assert_eq!(target.receipts.len(), 1);
    assert_eq!(target.receipts.get(&wrapped.requirement_id), Some(&wrapped));
}

#[test]
fn retry_increments_epoch_and_rejects_old_receipts() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let old_commands = begin_containment(&mut coordinator, &definition, "epoch1");
    coordinator
        .apply_simulation(&event(
            "epoch1.finalize",
            1,
            "2026-07-01T00:01:10.000Z",
            IncidentEventKindV1::FinalizeContainment,
        ))
        .expect("partial without receipts");
    assert_eq!(
        coordinator.snapshot().phase,
        IncidentPhase::ContainmentPartial
    );
    coordinator
        .apply_simulation(&event(
            "epoch2.retry",
            1,
            "2026-07-01T00:01:20.000Z",
            IncidentEventKindV1::RetryContainment {
                authorizations: containment_authorizations(&definition, "epoch2"),
            },
        ))
        .expect("retry containment");
    assert_eq!(coordinator.snapshot().isolation_epoch, 2);
    let old = receipt(&old_commands[0], "epoch1.old", EnforcementOutcome::Applied);
    assert!(
        coordinator
            .apply_simulation(&event(
                "epoch1.stale",
                1,
                "2026-07-01T00:01:21.000Z",
                IncidentEventKindV1::SubmitReceipt {
                    receipt: Box::new(old),
                },
            ))
            .is_err()
    );
    assert_eq!(coordinator.snapshot().isolation_epoch, 2);
}
