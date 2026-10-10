//! Regression coverage and synthetic evidence for document boundaries.
use super::*;

pub(super) fn authorization(
    target_id: &str,
    requirement_id: &str,
    binding: ActionBindingV1,
    tag: &str,
    assurance: AssuranceLevel,
) -> CommandAuthorizationV1 {
    let mut identity = identity(tag, assurance);
    identity.signed = sign_identity(&identity.signing_payload());
    let mut intent = intent(&identity, requirement_id, tag, binding.clone());
    intent.signed = sign_owner(&intent.signing_payload());
    let mut decision = decision(&identity, &intent, requirement_id, tag, binding.clone());
    decision.signed = sign_policy(&decision.signing_payload());
    let mut grant = grant(&identity, &intent, &decision, requirement_id, tag, binding);
    grant.signed = sign_policy(&grant.signing_payload());
    CommandAuthorizationV1 {
        target_id: target_id.to_owned(),
        requirement_id: requirement_id.to_owned(),
        current_revocation_epoch: 9,
        identity,
        intent,
        decision,
        grant,
    }
}
