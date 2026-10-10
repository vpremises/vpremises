//! Materialize bounded enforcement commands for the authorized phase.
use super::{
    BTreeMap, COORDINATOR_COMMAND_SCHEMA_V1, CommandAuthorizationV1, CoordinatorCommandV1,
    CoordinatorError, IncidentCoordinator, OperationMode, Validate,
};

impl IncidentCoordinator {
    pub(in crate::coordinator) fn begin_targets(
        &mut self,
        mode: OperationMode,
        epoch: u64,
        issued_at: &str,
        authorizations: &BTreeMap<String, CommandAuthorizationV1>,
    ) -> Result<Vec<CoordinatorCommandV1>, CoordinatorError> {
        let transaction_id = match mode {
            OperationMode::Containment => format!("tx.{epoch}.containment"),
            OperationMode::Restore => {
                format!("tx.{epoch}.restore.{}", self.snapshot.restore_attempt)
            }
        };
        let mut emitted = Vec::new();
        for target in self.snapshot.targets.values_mut() {
            let mut commands = BTreeMap::new();
            for requirement in &target.requirements {
                let authorization =
                    authorizations
                        .get(&requirement.requirement_id)
                        .ok_or_else(|| {
                            CoordinatorError::new(
                                "authorization",
                                "required authorization is missing",
                            )
                        })?;
                let command_id = match mode {
                    OperationMode::Containment => {
                        format!("cmd.{epoch}.containment.{}", requirement.requirement_id)
                    }
                    OperationMode::Restore => format!(
                        "cmd.{epoch}.restore.{}.{}",
                        self.snapshot.restore_attempt, requirement.requirement_id
                    ),
                };
                let command = CoordinatorCommandV1 {
                    schema: COORDINATOR_COMMAND_SCHEMA_V1.to_owned(),
                    command_id: command_id.clone(),
                    jti: command_id,
                    deployment_id: self.snapshot.deployment_id.clone(),
                    incident_id: self.snapshot.incident_id.clone(),
                    isolation_epoch: epoch,
                    transaction_id: transaction_id.clone(),
                    target_id: target.target_id.clone(),
                    requirement_id: requirement.requirement_id.clone(),
                    binding: authorization.intent.binding.clone(),
                    pep: authorization.intent.binding.audience.clone(),
                    enforcement_grant_jti: authorization.grant.jti.clone(),
                    issued_at: issued_at.to_owned(),
                    automatic: false,
                };
                command.validate()?;
                emitted.push(command.clone());
                commands.insert(requirement.requirement_id.clone(), command);
            }
            target.begin(mode, epoch, transaction_id.clone(), commands);
        }
        Ok(emitted)
    }
}
