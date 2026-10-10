use crowsi_control_contracts::ActionBindingV1;
use serde::{Deserialize, Serialize};

use crate::{
    COORDINATOR_COMMAND_SCHEMA_V1, CoordinatorError, Validate,
    validation::{binding, identifier, opaque, schema},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorCommandV1 {
    pub schema: String,
    pub command_id: String,
    pub jti: String,
    pub deployment_id: String,
    pub incident_id: String,
    pub isolation_epoch: u64,
    pub transaction_id: String,
    pub target_id: String,
    pub requirement_id: String,
    pub binding: ActionBindingV1,
    pub pep: String,
    pub enforcement_grant_jti: String,
    pub issued_at: String,
    pub automatic: bool,
}

impl CoordinatorCommandV1 {
    /// Returns the domain-separated digest bound into a signed checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the closed command cannot be serialized.
    pub fn canonical_digest(&self) -> Result<String, CoordinatorError> {
        let json = serde_json::to_vec(self)
            .map_err(|_| CoordinatorError::new("command", "canonical serialization failed"))?;
        let mut value = crate::canonical::Encoder::new("coordinator-command-v1");
        value.text("schema", &self.schema);
        value.text("json_digest", &crate::canonical::digest_payload(&json));
        Ok(crate::canonical::digest_payload(&value.finish()))
    }
}

impl Validate for CoordinatorCommandV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        schema(&self.schema, COORDINATOR_COMMAND_SCHEMA_V1)?;
        identifier("command_id", &self.command_id)?;
        identifier("jti", &self.jti)?;
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_id", &self.incident_id)?;
        if self.isolation_epoch == 0 {
            return Err(CoordinatorError::new("isolation_epoch", "must be positive"));
        }
        identifier("transaction_id", &self.transaction_id)?;
        opaque("target_id", &self.target_id, 256)?;
        identifier("requirement_id", &self.requirement_id)?;
        binding(&self.target_id, &self.binding)?;
        identifier("pep", &self.pep)?;
        if self.pep != self.binding.audience {
            return Err(CoordinatorError::new(
                "pep",
                "must equal the bound audience",
            ));
        }
        identifier("enforcement_grant_jti", &self.enforcement_grant_jti)?;
        crate::validation::timestamp("issued_at", &self.issued_at)?;
        if self.automatic {
            return Err(CoordinatorError::new(
                "automatic",
                "automatic enforcement is forbidden",
            ));
        }
        Ok(())
    }
}
