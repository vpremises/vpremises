use crate::support;

use crowsi_control_contracts::{AssuranceLevel, CanonicalPayloadV1};
use crowsi_incident_coordinator::{IncidentEventKindV1, IncidentPhase};

use support::{
    authorize_recovery, containment_authorizations, coordinator, definition, event,
    reach_recovery_pending, recovery_approval,
};

#[test]
fn automatic_restore_is_rejected_after_separate_approval() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    reach_recovery_pending(&mut coordinator, &definition, "auto");
    authorize_recovery(
        &mut coordinator,
        &definition,
        "auto.restore",
        "auto.approve",
    );
    assert_eq!(
        coordinator.snapshot().phase,
        IncidentPhase::RecoveryAuthorized
    );
    let before = coordinator.snapshot().clone();
    assert!(
        coordinator
            .apply_simulation(&event(
                "auto.denied",
                1,
                "2026-07-01T00:02:10.000Z",
                IncidentEventKindV1::StartRestore { automatic: true },
            ))
            .is_err()
    );
    assert_eq!(coordinator.snapshot(), &before);
}

#[test]
fn restore_requires_hardware_bound_step_up() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    reach_recovery_pending(&mut coordinator, &definition, "weak");
    let mut approval = recovery_approval(&definition, "weak.restore");
    for authorization in &mut approval.authorizations {
        authorization.identity.assurance = AssuranceLevel::PhishingResistant;
        authorization.identity.signed.digest = authorization.identity.payload_digest();
        authorization.decision.required_assurance = AssuranceLevel::PhishingResistant;
        authorization.decision.signed.digest = authorization.decision.payload_digest();
        authorization.grant.assurance = AssuranceLevel::PhishingResistant;
        authorization.grant.signed.digest = authorization.grant.payload_digest();
    }
    assert!(
        coordinator
            .apply_simulation(&event(
                "weak.approval",
                1,
                "2026-07-01T00:02:05.000Z",
                IncidentEventKindV1::AuthorizeRecovery {
                    approval: Box::new(approval),
                },
            ))
            .is_err()
    );
    assert_eq!(coordinator.snapshot().phase, IncidentPhase::RecoveryPending);
}

#[test]
fn recovery_cannot_reuse_containment_authorization() {
    let definition = definition();
    let mut coordinator = coordinator(definition.clone());
    reach_recovery_pending(&mut coordinator, &definition, "distinct");
    let used = containment_authorizations(&definition, "distinct");
    let mut approval = recovery_approval(&definition, "distinct.restore");
    let authorization = &mut approval.authorizations[0];
    authorization.intent.jti.clone_from(&used[0].intent.jti);
    authorization.intent.signed.digest = authorization.intent.payload_digest();
    authorization
        .decision
        .intent_jti
        .clone_from(&authorization.intent.jti);
    authorization.decision.signed.digest = authorization.decision.payload_digest();
    authorization
        .grant
        .intent_jti
        .clone_from(&authorization.intent.jti);
    authorization.grant.jti.clone_from(&used[0].grant.jti);
    authorization.grant.signed.digest = authorization.grant.payload_digest();
    assert!(
        coordinator
            .apply_simulation(&event(
                "distinct.reuse",
                1,
                "2026-07-01T00:02:05.000Z",
                IncidentEventKindV1::AuthorizeRecovery {
                    approval: Box::new(approval),
                },
            ))
            .is_err()
    );
}
