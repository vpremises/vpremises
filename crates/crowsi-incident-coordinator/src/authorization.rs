mod crypto;

pub(crate) use crypto::verify_signatures;

use crowsi_control_contracts::{
    DecisionEffect, EnforcementGrantV1, PolicyDecisionV1, SecurityIntentV1,
    VerifiedIdentityContextV1,
};
use serde::{Deserialize, Serialize};

use crate::{
    COORDINATOR_AUDIENCE, CoordinatorError, Validate,
    time::current,
    validation::{binding, identifier, opaque, timestamp},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandAuthorizationV1 {
    pub target_id: String,
    pub requirement_id: String,
    pub current_revocation_epoch: u64,
    pub identity: VerifiedIdentityContextV1,
    pub intent: SecurityIntentV1,
    pub decision: PolicyDecisionV1,
    pub grant: EnforcementGrantV1,
}

impl Validate for CommandAuthorizationV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        self.validate_at(&self.grant.issued_at)
    }
}

impl CommandAuthorizationV1 {
    /// Validates the pre-command authorization chain at a trusted caller time.
    ///
    /// # Errors
    ///
    /// Rejects stale, revoked, denied, downgraded, or cross-bound artifacts.
    pub fn validate_at(&self, at: &str) -> Result<(), CoordinatorError> {
        opaque("target_id", &self.target_id, 256)?;
        identifier("requirement_id", &self.requirement_id)?;
        timestamp("authorization_at", at)?;
        crowsi_control_contracts::Validate::validate(&self.identity)?;
        crowsi_control_contracts::Validate::validate(&self.intent)?;
        crowsi_control_contracts::Validate::validate(&self.decision)?;
        crowsi_control_contracts::Validate::validate(&self.grant)?;
        binding(&self.target_id, &self.intent.binding)?;
        if self.identity.audience != COORDINATOR_AUDIENCE
            || self.identity.revocation_epoch != self.current_revocation_epoch
        {
            return Err(CoordinatorError::new(
                "identity",
                "audience or revocation epoch is invalid",
            ));
        }
        self.validate_links()?;
        let live = current(
            &self.identity.authenticated_at,
            &self.identity.expires_at,
            at,
        ) && current(&self.intent.requested_at, &self.intent.expires_at, at)
            && current(&self.decision.issued_at, &self.decision.expires_at, at)
            && current(&self.grant.issued_at, &self.grant.expires_at, at);
        if live && self.validity_is_nested() {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "authorization_at",
                "authorization chain is not current",
            ))
        }
    }

    fn validate_links(&self) -> Result<(), CoordinatorError> {
        let identity = &self.identity;
        let same_identity = self.intent.identity_context_id == identity.context_id
            && self.intent.pairwise_subject == identity.pairwise_subject
            && self.intent.actor == identity.actor
            && self.intent.device == identity.device
            && self.intent.workload == identity.workload
            && self.intent.profile == identity.profile
            && self.intent.proof_key_ref == identity.proof_key_ref
            && self.intent.revocation_epoch == identity.revocation_epoch;
        let decision_matches = self.decision.intent_jti == self.intent.jti
            && self.decision.identity_context_id == identity.context_id
            && self.decision.pairwise_subject == identity.pairwise_subject
            && self.decision.actor == identity.actor
            && self.decision.device == identity.device
            && self.decision.workload == identity.workload
            && self.decision.profile == identity.profile
            && self.decision.proof_key_ref == identity.proof_key_ref
            && self.decision.revocation_epoch == identity.revocation_epoch
            && self.decision.binding == self.intent.binding
            && self.decision.effect == DecisionEffect::Permit;
        let grant_matches = self.grant.intent_jti == self.intent.jti
            && self.grant.decision_id == self.decision.decision_id
            && self.grant.identity_context_id == identity.context_id
            && self.grant.pairwise_subject == identity.pairwise_subject
            && self.grant.actor == identity.actor
            && self.grant.device == identity.device
            && self.grant.workload == identity.workload
            && self.grant.profile == identity.profile
            && self.grant.proof_key_ref == identity.proof_key_ref
            && self.grant.revocation_epoch == identity.revocation_epoch
            && self.grant.binding == self.intent.binding
            && self.grant.policy_digest == self.decision.policy_digest
            && self.grant.assurance == identity.assurance
            && identity.assurance.meets(self.decision.required_assurance);
        let distinct = self.intent.jti != self.grant.jti;
        if same_identity && decision_matches && grant_matches && distinct {
            Ok(())
        } else {
            Err(CoordinatorError::new(
                "authorization",
                "artifacts are not one exact authorization chain",
            ))
        }
    }

    fn validity_is_nested(&self) -> bool {
        self.identity.authenticated_at <= self.intent.requested_at
            && self.intent.expires_at <= self.identity.expires_at
            && self.intent.requested_at <= self.decision.issued_at
            && self.decision.expires_at <= self.intent.expires_at
            && self.decision.issued_at <= self.grant.issued_at
            && self.grant.expires_at <= self.decision.expires_at
    }
}
