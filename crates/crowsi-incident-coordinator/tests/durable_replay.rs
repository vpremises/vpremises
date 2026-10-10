use crate::support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{IncidentCoordinator, IncidentEventKindV1};

use support::{
    begin_containment, containment_authorizations, coordinator, definition, event, receipt, trust,
};

#[test]
fn restored_state_retains_replay_reservations_and_epoch() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    let commands = begin_containment(&mut coordinator, &definition, "durable");
    let wrapped = receipt(&commands[0], "durable.receipt", EnforcementOutcome::Applied);
    let receipt_event = event(
        "durable.receipt",
        1,
        "2026-07-01T00:01:10.000Z",
        IncidentEventKindV1::SubmitReceipt {
            receipt: Box::new(wrapped.clone()),
        },
    );
    coordinator
        .apply_simulation(&receipt_event)
        .expect("receipt");
    let state = coordinator.export_state();
    let mut corrupted = state.clone();
    corrupted.seen_receipt_jtis.clear();
    assert!(IncidentCoordinator::restore_simulation(corrupted, trust()).is_err());
    let mut restored =
        IncidentCoordinator::restore_simulation(state, trust()).expect("restore state");
    assert!(restored.apply_simulation(&receipt_event).is_err());
    restored
        .apply_simulation(&event(
            "durable.idempotent",
            1,
            "2026-07-01T00:01:11.000Z",
            IncidentEventKindV1::SubmitReceipt {
                receipt: Box::new(wrapped.clone()),
            },
        ))
        .expect("exact receipt is idempotent after restart");
    restored
        .apply_simulation(&event(
            "durable.finalize",
            1,
            "2026-07-01T00:01:12.000Z",
            IncidentEventKindV1::FinalizeContainment,
        ))
        .expect("partial containment");
    let before_reuse = restored.export_state();
    assert!(
        restored
            .apply_simulation(&event(
                "durable.reuse",
                1,
                "2026-07-01T00:01:13.000Z",
                IncidentEventKindV1::RetryContainment {
                    authorizations: containment_authorizations(&definition, "durable"),
                },
            ))
            .is_err()
    );
    assert_eq!(restored.export_state(), before_reuse);
    restored
        .apply_simulation(&event(
            "durable.retry",
            1,
            "2026-07-01T00:01:14.000Z",
            IncidentEventKindV1::RetryContainment {
                authorizations: containment_authorizations(&definition, "durable.next"),
            },
        ))
        .expect("fresh retry");
    assert_eq!(restored.snapshot().isolation_epoch, 2);
    assert!(
        restored
            .apply_simulation(&event(
                "durable.stale",
                1,
                "2026-07-01T00:01:15.000Z",
                IncidentEventKindV1::SubmitReceipt {
                    receipt: Box::new(wrapped),
                },
            ))
            .is_err()
    );
}
