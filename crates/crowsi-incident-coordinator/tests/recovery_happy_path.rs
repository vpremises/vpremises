use crate::support;

use crowsi_control_contracts::EnforcementOutcome;
use crowsi_incident_coordinator::{IncidentEventKindV1, IncidentPhase};

use support::{
    authorize_recovery, coordinator, definition, event, monitoring_evidence,
    reach_recovery_pending, submit_verified,
};

#[test]
fn manually_authorized_restore_can_reach_closed_without_changing_epoch() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    reach_recovery_pending(&mut coordinator, &definition, "happy");
    authorize_recovery(
        &mut coordinator,
        &definition,
        "happy.restore",
        "happy.approve",
    );
    let commands = coordinator
        .apply_simulation(&event(
            "happy.start",
            1,
            "2026-07-01T00:02:10.000Z",
            IncidentEventKindV1::StartRestore { automatic: false },
        ))
        .expect("start manual restore");
    assert_eq!(commands.len(), 2);
    assert!(commands.iter().all(|command| !command.automatic));
    assert_eq!(coordinator.snapshot().isolation_epoch, 1);
    for (index, command) in commands.iter().enumerate() {
        submit_verified(
            &mut coordinator,
            command,
            &format!("happy.restore.{index}"),
            EnforcementOutcome::Applied,
            &format!("2026-07-01T00:02:2{index}.000Z"),
        );
    }
    coordinator
        .apply_simulation(&event(
            "happy.restore.finalize",
            1,
            "2026-07-01T00:02:30.000Z",
            IncidentEventKindV1::FinalizeRestore,
        ))
        .expect("finalize restore");
    coordinator
        .apply_simulation(&event(
            "happy.monitor",
            1,
            "2026-07-01T00:02:31.000Z",
            IncidentEventKindV1::BeginMonitoring,
        ))
        .expect("begin monitoring");
    coordinator
        .apply_simulation(&event(
            "happy.close",
            1,
            "2026-07-01T00:07:33.000Z",
            IncidentEventKindV1::Close {
                evidence: Box::new(monitoring_evidence(&coordinator, "happy")),
            },
        ))
        .expect("close incident");
    assert_eq!(coordinator.snapshot().phase, IncidentPhase::Closed);
    assert_eq!(coordinator.snapshot().isolation_epoch, 1);
}
