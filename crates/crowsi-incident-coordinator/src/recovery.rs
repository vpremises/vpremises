pub(crate) mod authority;

use std::collections::{BTreeMap, BTreeSet};

use crowsi_control_contracts::{AssuranceLevel, ControlAction, RecoveryAuthorizationV1};
use serde::{Deserialize, Serialize};

use crate::{
    CommandAuthorizationV1, CoordinatorError,
    validation::{identifier, timestamp},
};

const MAX_AUTHORIZATIONS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApprovalV1 {
    pub approval_id: String,
    pub approved_at: String,
    pub authorizations: Vec<CommandAuthorizationV1>,
    pub recovery_authorizations: BTreeMap<String, RecoveryAuthorizationV1>,
}

impl RecoveryApprovalV1 {
    pub(crate) fn validate_at(&self, at: &str) -> Result<(), CoordinatorError> {
        identifier("approval_id", &self.approval_id)?;
        timestamp("approved_at", &self.approved_at)?;
        if self.approved_at.as_str() > at
            || self.authorizations.is_empty()
            || self.authorizations.len() > MAX_AUTHORIZATIONS
            || self.recovery_authorizations.len() != self.authorizations.len()
        {
            return Err(CoordinatorError::new(
                "authorizations",
                "approval timing or authorization count is invalid",
            ));
        }
        let mut requirements = BTreeSet::new();
        let mut grants = BTreeSet::new();
        let mut recovery_jtis = BTreeSet::new();
        let mut context: Option<&str> = None;
        for authorization in &self.authorizations {
            authorization.validate_at(at)?;
            if authorization.intent.binding.action != ControlAction::Restore
                || authorization.identity.assurance != AssuranceLevel::HardwareBoundStepUp
                || authorization.decision.required_assurance != AssuranceLevel::HardwareBoundStepUp
            {
                return Err(CoordinatorError::new(
                    "recovery_assurance",
                    "restore requires hardware-bound step-up",
                ));
            }
            if !requirements.insert(&authorization.requirement_id)
                || !grants.insert(&authorization.grant.jti)
            {
                return Err(CoordinatorError::new(
                    "authorizations",
                    "requirements and one-use grants must be unique",
                ));
            }
            match context {
                None => context = Some(&authorization.identity.context_id),
                Some(expected) if expected != authorization.identity.context_id => {
                    return Err(CoordinatorError::new(
                        "identity_context_id",
                        "one recovery approval must use one identity context",
                    ));
                }
                Some(_) => {}
            }
            let recovery = self
                .recovery_authorizations
                .get(&authorization.requirement_id)
                .ok_or_else(|| {
                    CoordinatorError::new(
                        "recovery_authorizations",
                        "signed authority is missing for a requirement",
                    )
                })?;
            recovery.validate_at(at)?;
            if !recovery_jtis.insert(&recovery.jti) {
                return Err(CoordinatorError::new(
                    "recovery_authorizations",
                    "signed authority JTIs must be unique",
                ));
            }
        }
        Ok(())
    }
}
