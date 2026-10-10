use crate::support;

use crowsi_incident_coordinator::{CoordinatorStateV1, IncidentCoordinator, IncidentEventKindV1};

use support::{
    anchor, checkpoint, coordinator, current_head, definition, event, reach_recovery_pending,
    recovery_approval, restore_challenge, trust, trust_digest,
};

#[test]
fn checkpoint_round_trip_preserves_pending_manual_recovery() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    reach_recovery_pending(&mut coordinator, &definition, "restart");
    let authorization_event = event(
        "restart.authorize",
        1,
        "2026-07-01T00:02:05.000Z",
        IncidentEventKindV1::AuthorizeRecovery {
            approval: Box::new(recovery_approval(&definition, "restart.restore")),
        },
    );
    coordinator
        .apply_simulation(&authorization_event)
        .expect("authorize recovery");
    let exported = coordinator.export_state();
    assert!(exported.pending_recovery.is_some());
    assert!(!exported.seen_event_jtis.is_empty());
    assert!(!exported.seen_receipt_jtis.is_empty());
    assert!(!exported.reserved_authorization_jtis.is_empty());
    assert!(!exported.used_approval_ids.is_empty());
    let mut incomplete = exported.clone();
    incomplete.pending_recovery = None;
    assert!(IncidentCoordinator::restore_simulation(incomplete, trust()).is_err());
    let mut mismatched_epoch = exported.clone();
    mismatched_epoch.snapshot.isolation_epoch = 2;
    assert!(IncidentCoordinator::restore_simulation(mismatched_epoch, trust()).is_err());
    let encoded = serde_json::to_vec(&exported).expect("serialize state");
    let decoded: CoordinatorStateV1 = serde_json::from_slice(&encoded).expect("deserialize state");
    let signed_checkpoint = checkpoint(&decoded, 1, None);
    let challenge = restore_challenge();
    let external_anchor = anchor(&signed_checkpoint, &challenge);
    let production = IncidentCoordinator::restore_authenticated(
        decoded.clone(),
        &signed_checkpoint,
        &external_anchor,
        challenge,
        &trust_digest(),
        trust(),
        &current_head(&signed_checkpoint),
    )
    .expect("restore authenticated state");
    assert!(production.checkpoint_required());
    assert!(production.snapshot().trusted_time_watermark >= signed_checkpoint.issued_at);
    let mut restored =
        IncidentCoordinator::restore_simulation(decoded, trust()).expect("restore state");
    assert_eq!(restored.export_state(), exported);
    assert!(restored.apply_simulation(&authorization_event).is_err());
    let commands = restored
        .apply_simulation(&event(
            "restart.start",
            1,
            "2026-07-01T00:02:10.000Z",
            IncidentEventKindV1::StartRestore { automatic: false },
        ))
        .expect("consume persisted approval");
    assert_eq!(commands.len(), 2);
    assert_eq!(restored.snapshot().isolation_epoch, 1);
}
