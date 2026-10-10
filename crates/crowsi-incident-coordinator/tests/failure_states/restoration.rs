//! Regression coverage and synthetic evidence for restoration boundaries.
use super::*;

#[test]
fn partial_restore_returns_to_new_recovery_approval() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    reach_recovery_pending(&mut coordinator, &definition, "restorepartial");
    authorize_recovery(
        &mut coordinator,
        &definition,
        "restorepartial.approval",
        "restorepartial.authorize",
    );
    let commands = coordinator
        .apply_simulation(&event(
            "restorepartial.start",
            1,
            "2026-07-01T00:02:10.000Z",
            IncidentEventKindV1::StartRestore { automatic: false },
        ))
        .expect("start restore");
    submit(
        &mut coordinator,
        &commands[0],
        "restorepartial.applied",
        EnforcementOutcome::Applied,
        "2026-07-01T00:02:20.000Z",
    );
    submit(
        &mut coordinator,
        &commands[1],
        "restorepartial.failed",
        EnforcementOutcome::Failed,
        "2026-07-01T00:02:21.000Z",
    );
    coordinator
        .apply_simulation(&event(
            "restorepartial.restore.finalize",
            1,
            "2026-07-01T00:02:30.000Z",
            IncidentEventKindV1::FinalizeRestore,
        ))
        .expect("finalize partial restore");
    assert_eq!(coordinator.snapshot().phase, IncidentPhase::RestorePartial);
    coordinator
        .apply_simulation(&event(
            "restorepartial.retry",
            1,
            "2026-07-01T00:02:31.000Z",
            IncidentEventKindV1::RetryRecovery,
        ))
        .expect("retry recovery");
    assert_eq!(coordinator.snapshot().phase, IncidentPhase::RecoveryPending);
    assert!(coordinator.snapshot().recovery_approval_id.is_none());
    let first_transaction = commands[0].transaction_id.clone();
    let first_jtis = commands
        .iter()
        .map(|command| command.jti.clone())
        .collect::<Vec<_>>();
    coordinator
        .apply_simulation(&event(
            "restorepartial.authorize.second",
            1,
            "2026-07-01T00:02:32.000Z",
            IncidentEventKindV1::AuthorizeRecovery {
                approval: Box::new(recovery_approval(
                    &definition,
                    "restorepartial.approval.second",
                )),
            },
        ))
        .expect("authorize second restore");
    let second = coordinator
        .apply_simulation(&event(
            "restorepartial.start.second",
            1,
            "2026-07-01T00:02:33.000Z",
            IncidentEventKindV1::StartRestore { automatic: false },
        ))
        .expect("start second restore");
    assert_eq!(coordinator.snapshot().restore_attempt, 2);
    assert_ne!(second[0].transaction_id, first_transaction);
    assert!(
        second
            .iter()
            .all(|command| !first_jtis.contains(&command.jti))
    );
}
