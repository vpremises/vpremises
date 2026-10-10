use std::collections::BTreeSet;

use crowsi_control_contracts::CanonicalPayloadV1;

use crate::{
    CoordinatorError, CoordinatorTrustV1, RecoveryApprovalV1,
    trust::{TrustRole, TrustScope},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayExpectation {
    Fresh,
    Recorded,
}

pub(crate) fn verify(
    approval: &RecoveryApprovalV1,
    incident_id: &str,
    trust: &CoordinatorTrustV1,
    at: &str,
    reserved: &BTreeSet<String>,
    seen_evidence: &BTreeSet<String>,
    replay: ReplayExpectation,
) -> Result<Vec<String>, CoordinatorError> {
    approval.validate_at(at)?;
    let mut accepted = Vec::with_capacity(approval.authorizations.len());
    for authorization in &approval.authorizations {
        let signed = approval
            .recovery_authorizations
            .get(&authorization.requirement_id)
            .ok_or_else(|| {
                CoordinatorError::new("recovery_authorizations", "signed authority is missing")
            })?;
        let exact = signed.incident_id == incident_id
            && signed.binding == authorization.intent.binding
            && signed.identity_context_id == authorization.identity.context_id
            && signed.pairwise_subject == authorization.identity.pairwise_subject
            && signed.authoritative_revocation_epoch == authorization.current_revocation_epoch
            && signed.policy_snapshot_digest == authorization.decision.policy_digest
            && signed.jti != authorization.intent.jti
            && signed.jti != authorization.grant.jti
            && !reserved.contains(&signed.jti);
        let replay_valid = match replay {
            ReplayExpectation::Fresh => !seen_evidence.contains(&signed.jti),
            ReplayExpectation::Recorded => seen_evidence.contains(&signed.jti),
        };
        if !exact || !replay_valid {
            return Err(CoordinatorError::new(
                "recovery_authorization",
                "binding, revocation, policy, or replay state is invalid",
            ));
        }
        trust.verify(
            None,
            TrustRole::RecoveryAuthority,
            TrustScope::Recovery,
            &signed.signed,
            &signed.signing_payload(),
        )?;
        accepted.push(signed.jti.clone());
    }
    Ok(accepted)
}
