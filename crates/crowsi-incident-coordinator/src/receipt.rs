use crowsi_control_contracts::EnforcementReceiptV1;
use serde::{Deserialize, Serialize};

use crate::{
    COORDINATOR_RECEIPT_SCHEMA_V1, CoordinatorCommandV1, CoordinatorError, Validate,
    validation::{binding, identifier, opaque, schema},
};

pub(crate) fn matches_command(
    receipt: &CoordinatorReceiptV1,
    command: &CoordinatorCommandV1,
) -> bool {
    receipt.deployment_id == command.deployment_id
        && receipt.incident_id == command.incident_id
        && receipt.isolation_epoch == command.isolation_epoch
        && receipt.transaction_id == command.transaction_id
        && receipt.target_id == command.target_id
        && receipt.requirement_id == command.requirement_id
        && receipt.enforcement.command_jti == command.jti
        && receipt.enforcement.enforcement_grant_jti == command.enforcement_grant_jti
        && receipt.enforcement.binding == command.binding
        && receipt.enforcement.provider == command.pep
        && receipt.enforcement.applied_at >= command.issued_at
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorReceiptV1 {
    pub schema: String,
    pub receipt_jti: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub isolation_epoch: u64,
    pub transaction_id: String,
    pub target_id: String,
    pub requirement_id: String,
    pub enforcement: EnforcementReceiptV1,
}

impl Validate for CoordinatorReceiptV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, COORDINATOR_RECEIPT_SCHEMA_V1)?;
        identifier("receipt_jti", &self.receipt_jti)?;
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_id", &self.incident_id)?;
        if self.isolation_epoch == 0 {
            return Err(CoordinatorError::new("isolation_epoch", "must be positive"));
        }
        identifier("transaction_id", &self.transaction_id)?;
        opaque("target_id", &self.target_id, 256)?;
        identifier("requirement_id", &self.requirement_id)?;
        crowsi_control_contracts::Validate::validate(&self.enforcement)?;
        binding(&self.target_id, &self.enforcement.binding)?;
        if self.receipt_jti != self.enforcement.receipt_id {
            return Err(CoordinatorError::new(
                "receipt_jti",
                "must equal the enforcement receipt identifier",
            ));
        }
        Ok(())
    }
}
