use std::collections::{BTreeMap, BTreeSet};

use crowsi_control_contracts::{ActionBindingV1, ControlAction};

use crate::{
    COORDINATOR_COMMAND_SCHEMA_V1, CommandAuthorizationV1, CoordinatorCommandV1, CoordinatorError,
    IncidentCoordinator, OperationMode, Validate, authorization::verify_signatures,
};

impl IncidentCoordinator {
    pub(super) fn validate_authorizations(
        &self,
        mode: OperationMode,
        authorizations: &[CommandAuthorizationV1],
        at: &str,
        owner_authority: &str,
    ) -> Result<BTreeMap<String, CommandAuthorizationV1>, CoordinatorError> {
        let mut expected = self.expected_bindings(mode);
        if authorizations.len() != expected.len() {
            return Err(CoordinatorError::new(
                "authorizations",
                "one authorization is required per enforcement",
            ));
        }
        let mut mapped = BTreeMap::new();
        let mut fresh_jtis = BTreeSet::new();
        for authorization in authorizations {
            authorization.validate_at(at)?;
            verify_signatures(authorization, &self.trust, mode, Some(owner_authority))?;
            let Some((target, binding)) = expected.remove(&authorization.requirement_id) else {
                return Err(CoordinatorError::new(
                    "requirement_id",
                    "authorization is not required",
                ));
            };
            let jtis = [&authorization.intent.jti, &authorization.grant.jti];
            let fresh = jtis.into_iter().all(|jti| {
                !self.reserved_authorization_jtis.contains(jti) && fresh_jtis.insert(jti)
            });
            if authorization.target_id != target
                || authorization.intent.binding != binding
                || !fresh
                || mapped
                    .insert(authorization.requirement_id.clone(), authorization.clone())
                    .is_some()
            {
                return Err(CoordinatorError::new(
                    "authorization",
                    "authorization binding or JTI is invalid",
                ));
            }
        }
        Ok(mapped)
    }

    fn expected_bindings(
        &self,
        mode: OperationMode,
    ) -> BTreeMap<String, (String, ActionBindingV1)> {
        let mut expected = BTreeMap::new();
        for target in self.snapshot.targets.values() {
            for requirement in &target.requirements {
                let mut binding = requirement.binding.clone();
                if mode == OperationMode::Restore {
                    binding.action = ControlAction::Restore;
                    "incident-recovery".clone_into(&mut binding.purpose);
                }
                expected.insert(
                    requirement.requirement_id.clone(),
                    (target.target_id.clone(), binding),
                );
            }
        }
        expected
    }

    pub(super) fn begin_targets(
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
    pub(super) fn reserve(&mut self, authorizations: &BTreeMap<String, CommandAuthorizationV1>) {
        for authorization in authorizations.values() {
            self.reserved_authorization_jtis
                .insert(authorization.intent.jti.clone());
            self.reserved_authorization_jtis
                .insert(authorization.grant.jti.clone());
        }
    }
}
