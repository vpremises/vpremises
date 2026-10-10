use crowsi_control_contracts::{
    ActionBindingV1, AssuranceLevel, DecisionEffect, ENFORCEMENT_GRANT_SCHEMA_V1,
    EnforcementGrantV1, POLICY_DECISION_SCHEMA_V1, PolicyDecisionV1, SECURITY_INTENT_SCHEMA_V1,
    SecurityIntentV1, VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1, VerifiedIdentityContextV1,
};
use crowsi_incident_coordinator::COORDINATOR_AUDIENCE;

use super::super::common::{digest, signed};

pub(super) fn identity(tag: &str, assurance: AssuranceLevel) -> VerifiedIdentityContextV1 {
    VerifiedIdentityContextV1 {
        schema: VERIFIED_IDENTITY_CONTEXT_SCHEMA_V1.to_owned(),
        context_id: format!("ctx.{tag}"),
        issuer: super::super::crypto::IDENTITY_AUTHORITY.to_owned(),
        pairwise_subject: "pairwise-user-a".to_owned(),
        actor: "user-a".to_owned(),
        device: "device-a".to_owned(),
        workload: "spiffe://crowsi.local/hatter/session-a".to_owned(),
        profile: "profile-private".to_owned(),
        proof_key_ref: "jkt:proof-key-a".to_owned(),
        assurance,
        authorization_grant_id: format!("identity-grant.{tag}"),
        revocation_epoch: 9,
        authenticated_at: "2026-07-01T00:00:00.000Z".to_owned(),
        expires_at: "2026-07-01T00:10:00.000Z".to_owned(),
        audience: COORDINATOR_AUDIENCE.to_owned(),
        signed: signed(),
    }
}

pub(super) fn intent(
    identity: &VerifiedIdentityContextV1,
    requirement: &str,
    tag: &str,
    binding: ActionBindingV1,
) -> SecurityIntentV1 {
    SecurityIntentV1 {
        schema: SECURITY_INTENT_SCHEMA_V1.to_owned(),
        intent_id: format!("intent.{tag}.{requirement}"),
        jti: format!("jti.intent.{tag}.{requirement}"),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding,
        requested_at: "2026-07-01T00:00:30.000Z".to_owned(),
        expires_at: "2026-07-01T00:05:00.000Z".to_owned(),
        reason: "coordinate incident response".to_owned(),
        signed: signed(),
    }
}

pub(super) fn decision(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    requirement: &str,
    tag: &str,
    binding: ActionBindingV1,
) -> PolicyDecisionV1 {
    PolicyDecisionV1 {
        schema: POLICY_DECISION_SCHEMA_V1.to_owned(),
        decision_id: format!("decision.{tag}.{requirement}"),
        intent_jti: intent.jti.clone(),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        effect: DecisionEffect::Permit,
        binding,
        required_assurance: intent.binding.action.required_assurance(),
        issued_at: "2026-07-01T00:00:40.000Z".to_owned(),
        expires_at: "2026-07-01T00:04:00.000Z".to_owned(),
        policy_digest: digest(),
        signed: signed(),
    }
}

pub(super) fn grant(
    identity: &VerifiedIdentityContextV1,
    intent: &SecurityIntentV1,
    decision: &PolicyDecisionV1,
    requirement: &str,
    tag: &str,
    binding: ActionBindingV1,
) -> EnforcementGrantV1 {
    EnforcementGrantV1 {
        schema: ENFORCEMENT_GRANT_SCHEMA_V1.to_owned(),
        grant_id: format!("grant.{tag}.{requirement}"),
        jti: format!("jti.grant.{tag}.{requirement}"),
        decision_id: decision.decision_id.clone(),
        intent_jti: intent.jti.clone(),
        identity_context_id: identity.context_id.clone(),
        pairwise_subject: identity.pairwise_subject.clone(),
        actor: identity.actor.clone(),
        device: identity.device.clone(),
        workload: identity.workload.clone(),
        profile: identity.profile.clone(),
        proof_key_ref: identity.proof_key_ref.clone(),
        revocation_epoch: identity.revocation_epoch,
        binding,
        assurance: identity.assurance,
        issued_at: "2026-07-01T00:00:50.000Z".to_owned(),
        expires_at: "2026-07-01T00:02:50.000Z".to_owned(),
        use_limit: 1,
        policy_digest: decision.policy_digest.clone(),
        signed: signed(),
    }
}
