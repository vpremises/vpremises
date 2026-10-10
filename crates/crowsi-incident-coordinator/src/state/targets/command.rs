use std::collections::BTreeSet;

use crowsi_control_contracts::ControlAction;

use crate::{
    CoordinatorError, CoordinatorStateV1, CoordinatorTrustV1, DesiredTargetState,
    ObservedTargetState, OperationMode, TargetStateV1, TransactionState, Validate,
};

use super::receipt::{validate_aggregate, validate_receipt};

pub(super) fn validate(
    state: &CoordinatorStateV1,
    trust: &CoordinatorTrustV1,
    target: &TargetStateV1,
    command_jtis: &mut BTreeSet<String>,
    grant_jtis: &mut BTreeSet<String>,
    receipt_jtis: &mut BTreeSet<String>,
    transaction_ids: &mut BTreeSet<String>,
) -> Result<(), CoordinatorError> {
    if state.snapshot.isolation_epoch == 0 {
        return validate_idle(target);
    }
    let mode = match target.desired {
        DesiredTargetState::Isolated => OperationMode::Containment,
        DesiredTargetState::Restored => OperationMode::Restore,
        DesiredTargetState::Unchanged => {
            return Err(CoordinatorError::new(
                "desired",
                "must be an active operation",
            ));
        }
    };
    let transaction_id = target
        .transaction_id
        .as_ref()
        .ok_or_else(|| CoordinatorError::new("transaction_id", "must be present"))?;
    transaction_ids.insert(transaction_id.clone());
    if target.active_commands.len() != target.requirements.len()
        || target.receipts.len() > target.active_commands.len()
        || target.verified_evidence.len() > target.receipts.len()
        || !target
            .receipts
            .keys()
            .all(|requirement_id| target.active_commands.contains_key(requirement_id))
        || !target
            .verified_evidence
            .keys()
            .all(|requirement_id| target.receipts.contains_key(requirement_id))
    {
        return Err(CoordinatorError::new(
            "active_commands",
            "must exactly cover the target requirements",
        ));
    }
    for requirement in &target.requirements {
        let command = target
            .active_commands
            .get(&requirement.requirement_id)
            .ok_or_else(|| CoordinatorError::new("active_commands", "command is missing"))?;
        command.validate()?;
        let mut binding = requirement.binding.clone();
        if mode == OperationMode::Restore {
            binding.action = ControlAction::Restore;
            "incident-recovery".clone_into(&mut binding.purpose);
        }
        let expected_transaction = match mode {
            OperationMode::Containment => {
                format!("tx.{}.containment", state.snapshot.isolation_epoch)
            }
            OperationMode::Restore => format!(
                "tx.{}.restore.{}",
                state.snapshot.isolation_epoch, state.snapshot.restore_attempt
            ),
        };
        let expected_command = match mode {
            OperationMode::Containment => format!(
                "cmd.{}.containment.{}",
                state.snapshot.isolation_epoch, requirement.requirement_id
            ),
            OperationMode::Restore => format!(
                "cmd.{}.restore.{}.{}",
                state.snapshot.isolation_epoch,
                state.snapshot.restore_attempt,
                requirement.requirement_id
            ),
        };
        let consistent = command.deployment_id == state.snapshot.deployment_id
            && command.incident_id == state.snapshot.incident_id
            && command.isolation_epoch == state.snapshot.isolation_epoch
            && command.transaction_id == *transaction_id
            && command.transaction_id == expected_transaction
            && command.target_id == target.target_id
            && command.requirement_id == requirement.requirement_id
            && command.binding == binding
            && command.command_id == expected_command
            && command.jti == command.command_id
            && command.issued_at >= state.snapshot.detected_at
            && command.issued_at <= state.snapshot.trusted_time_watermark
            && command_jtis.insert(command.jti.clone())
            && grant_jtis.insert(command.enforcement_grant_jti.clone())
            && state
                .reserved_authorization_jtis
                .contains(&command.enforcement_grant_jti);
        if !consistent {
            return Err(CoordinatorError::new(
                "active_commands",
                "command state is inconsistent",
            ));
        }
        validate_receipt(state, trust, target, command, receipt_jtis)?;
    }
    validate_aggregate(target, mode)
}

fn validate_idle(target: &TargetStateV1) -> Result<(), CoordinatorError> {
    let valid = target.desired == DesiredTargetState::Unchanged
        && target.observed == ObservedTargetState::Unknown
        && target.transaction == TransactionState::Idle
        && target.transaction_id.is_none()
        && target.active_commands.is_empty()
        && target.receipts.is_empty()
        && target.verified_evidence.is_empty();
    if valid {
        Ok(())
    } else {
        Err(CoordinatorError::new(
            "target",
            "epoch zero target must be idle",
        ))
    }
}
