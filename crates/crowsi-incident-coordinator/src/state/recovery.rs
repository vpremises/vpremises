use std::collections::{BTreeMap, BTreeSet};

use crowsi_control_contracts::ControlAction;

use crate::{
    CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1, IncidentPhase, OperationMode,
    Validate,
    authorization::verify_signatures,
    recovery::authority::{ReplayExpectation, verify as verify_recovery_authority},
    validation::identifier,
};

pub(super) fn validate(
    state: &CoordinatorStateV1,
    trust: &CoordinatorTrustV1,
) -> Result<(), CoordinatorError> {
    if let Some(approval_id) = &state.snapshot.recovery_approval_id {
        identifier("recovery_approval_id", approval_id)?;
        if !state.used_approval_ids.contains(approval_id) {
            return Err(CoordinatorError::new(
                "used_approval_ids",
                "must include the active recovery approval",
            ));
        }
    }
    match (&state.snapshot.phase, &state.pending_recovery) {
        (IncidentPhase::RecoveryAuthorized, Some(approval)) => {
            approval.validate_at(&state.snapshot.last_event_at)?;
            if state.snapshot.recovery_approval_id.as_ref() != Some(&approval.approval_id)
                || !state.used_approval_ids.contains(&approval.approval_id)
            {
                return Err(CoordinatorError::new(
                    "pending_recovery",
                    "must match the active used approval",
                ));
            }
            validate_authorizations(state, approval, trust)?;
            verify_recovery_authority(
                approval,
                &state.snapshot.incident_id,
                trust,
                &state.snapshot.last_event_at,
                &state.reserved_authorization_jtis,
                &state.seen_evidence_jtis,
                ReplayExpectation::Recorded,
            )?;
            Ok(())
        }
        (IncidentPhase::RecoveryAuthorized, None) => Err(CoordinatorError::new(
            "pending_recovery",
            "recovery-authorized requires the approval payload",
        )),
        (_, Some(_)) => Err(CoordinatorError::new(
            "pending_recovery",
            "is only valid while recovery is authorized",
        )),
        _ => Ok(()),
    }
}

fn validate_authorizations(
    state: &CoordinatorStateV1,
    approval: &crate::RecoveryApprovalV1,
    trust: &CoordinatorTrustV1,
) -> Result<(), CoordinatorError> {
    let mut expected = BTreeMap::new();
    for target in state.snapshot.targets.values() {
        for requirement in &target.requirements {
            let mut binding = requirement.binding.clone();
            binding.action = ControlAction::Restore;
            "incident-recovery".clone_into(&mut binding.purpose);
            expected.insert(
                requirement.requirement_id.as_str(),
                (target.target_id.as_str(), binding),
            );
        }
    }
    if approval.authorizations.len() != expected.len() {
        return Err(CoordinatorError::new(
            "pending_recovery.authorizations",
            "must cover every enforcement requirement",
        ));
    }
    let mut jtis = BTreeSet::new();
    for authorization in &approval.authorizations {
        authorization.validate()?;
        verify_signatures(authorization, trust, OperationMode::Restore, None)?;
        let Some((target_id, binding)) = expected.remove(authorization.requirement_id.as_str())
        else {
            return Err(CoordinatorError::new(
                "pending_recovery.requirement_id",
                "is not an expected enforcement requirement",
            ));
        };
        let fresh = [&authorization.intent.jti, &authorization.grant.jti]
            .into_iter()
            .all(|jti| !state.reserved_authorization_jtis.contains(jti) && jtis.insert(jti));
        if authorization.target_id != target_id || authorization.intent.binding != binding || !fresh
        {
            return Err(CoordinatorError::new(
                "pending_recovery.authorization",
                "binding or one-use JTI is inconsistent",
            ));
        }
    }
    Ok(())
}
