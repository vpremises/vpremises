use std::collections::BTreeSet;

use crowsi_control_contracts::{ActionBindingV1, ControlAction};
use serde::{Deserialize, Serialize};

use crate::{
    CoordinatorError, Validate,
    validation::{binding, identifier, opaque, timestamp},
};

const MAX_TARGETS: usize = 64;
const MAX_REQUIREMENTS_PER_TARGET: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnforcementRequirementV1 {
    pub requirement_id: String,
    pub binding: ActionBindingV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetDefinitionV1 {
    pub target_id: String,
    pub requirements: Vec<EnforcementRequirementV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentDefinitionV1 {
    pub deployment_id: String,
    pub incident_owner_authority: String,
    pub incident_id: String,
    pub detected_at: String,
    pub targets: Vec<TargetDefinitionV1>,
}

impl Validate for IncidentDefinitionV1 {
    fn validate(&self) -> Result<(), CoordinatorError> {
        identifier("deployment_id", &self.deployment_id)?;
        identifier("incident_owner_authority", &self.incident_owner_authority)?;
        identifier("incident_id", &self.incident_id)?;
        timestamp("detected_at", &self.detected_at)?;
        if self.targets.is_empty() || self.targets.len() > MAX_TARGETS {
            return Err(CoordinatorError::new(
                "targets",
                "must contain between 1 and 64 targets",
            ));
        }
        let mut targets = BTreeSet::new();
        let mut requirements = BTreeSet::new();
        for target in &self.targets {
            opaque("target_id", &target.target_id, 256)?;
            if !targets.insert(&target.target_id) {
                return Err(CoordinatorError::new("target_id", "must be unique"));
            }
            if target.requirements.is_empty()
                || target.requirements.len() > MAX_REQUIREMENTS_PER_TARGET
            {
                return Err(CoordinatorError::new(
                    "requirements",
                    "must contain between 1 and 16 entries",
                ));
            }
            for requirement in &target.requirements {
                identifier("requirement_id", &requirement.requirement_id)?;
                if !requirements.insert(&requirement.requirement_id) {
                    return Err(CoordinatorError::new(
                        "requirement_id",
                        "must be globally unique",
                    ));
                }
                binding(&target.target_id, &requirement.binding)?;
                if requirement.binding.action == ControlAction::Restore
                    || requirement.binding.purpose != "incident-containment"
                {
                    return Err(CoordinatorError::new(
                        "requirement.binding",
                        "must describe a containment action",
                    ));
                }
            }
        }
        Ok(())
    }
}
