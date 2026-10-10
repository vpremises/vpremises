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

mod validation;

mod chain;
