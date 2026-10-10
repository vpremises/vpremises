mod command;
mod receipt;

use std::collections::BTreeSet;

use crate::{
    CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1, IncidentDefinitionV1,
    TargetDefinitionV1, Validate,
};

pub(super) fn validate(
    state: &CoordinatorStateV1,
    trust: &CoordinatorTrustV1,
) -> Result<(), CoordinatorError> {
    let definition = IncidentDefinitionV1 {
        deployment_id: state.snapshot.deployment_id.clone(),
        incident_owner_authority: state.snapshot.incident_owner_authority.clone(),
        incident_id: state.snapshot.incident_id.clone(),
        detected_at: state.snapshot.detected_at.clone(),
        targets: state
            .snapshot
            .targets
            .values()
            .map(|target| TargetDefinitionV1 {
                target_id: target.target_id.clone(),
                requirements: target.requirements.clone(),
            })
            .collect(),
    };
    definition.validate()?;
    let mut command_jtis = BTreeSet::new();
    let mut grant_jtis = BTreeSet::new();
    let mut receipt_jtis = BTreeSet::new();
    let mut transaction_ids = BTreeSet::new();
    let mut desired = BTreeSet::new();
    for (target_id, target) in &state.snapshot.targets {
        if target_id != &target.target_id
            || target.isolation_epoch != state.snapshot.isolation_epoch
        {
            return Err(CoordinatorError::new(
                "target",
                "map key or isolation epoch is inconsistent",
            ));
        }
        command::validate(
            state,
            trust,
            target,
            &mut command_jtis,
            &mut grant_jtis,
            &mut receipt_jtis,
            &mut transaction_ids,
        )?;
        desired.insert(target.desired as u8);
    }
    if desired.len() > 1 || transaction_ids.len() > 1 {
        return Err(CoordinatorError::new(
            "targets",
            "must share one desired state and transaction",
        ));
    }
    Ok(())
}
